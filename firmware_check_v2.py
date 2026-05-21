```python
"""
firmware_compliance_checker.py - Audit network devices against a firmware baseline.

Purpose:
    Reads a device inventory CSV specifying each host's minimum acceptable
    firmware version, connects via SSH, extracts the running version, and
    reports PASS/FAIL compliance.  Unlike a simple version display script,
    this tool enforces a declared policy and exits non-zero when any device
    is out of compliance — making it suitable for scheduled audits or CI gates.

Usage:
    python firmware_compliance_checker.py \
        --inventory devices.csv \
        --username admin \
        --password secret \
        [--output report.csv] \
        [--timeout 30] \
        [--verbose]

    Inventory CSV columns (header row required):
        host, device_type, min_version

    Example row:
        10.0.0.1,cisco_ios,15.6(3)M

    Supported device_type values:
        cisco_ios, cisco_xe, cisco_nxos, cisco_asa, arista_eos,
        juniper_junos, hp_procurve

Prerequisites:
    pip install netmiko
    Python 3.8+
"""

import argparse
import csv
import logging
import re
import sys
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

VERSION_COMMANDS = {
    "cisco_ios": "show version",
    "cisco_xe": "show version",
    "cisco_nxos": "show version",
    "cisco_asa": "show version",
    "arista_eos": "show version",
    "juniper_junos": "show version",
    "hp_procurve": "show version",
}

VERSION_PATTERNS = {
    "cisco_ios": r"Version\s+([\d\w\(\).]+),",
    "cisco_xe": r"Cisco IOS XE Software.*?Version\s+([\d\w\(\).]+)",
    "cisco_nxos": r"NXOS:\s+version\s+([\d\w\(\).]+)",
    "cisco_asa": r"Software Version\s+([\d\w\(\).]+)",
    "arista_eos": r"EOS version:\s+([\d\w.]+)",
    "juniper_junos": r"Junos:\s+([\d\w.R-]+)",
    "hp_procurve": r"Software revision\s*:\s*([\d\w.]+)",
}


def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.DEBUG if verbose else logging.INFO,
        stream=sys.stdout,
    )


def load_inventory(path: str) -> list:
    devices = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        required = {"host", "device_type", "min_version"}
        if not required.issubset(set(reader.fieldnames or [])):
            raise ValueError(f"Inventory CSV must contain columns: {required}")
        for row in reader:
            row = {k.strip(): v.strip() for k, v in row.items()}
            if row["device_type"] not in VERSION_COMMANDS:
                logging.warning(
                    "Unsupported device_type '%s' for %s — skipping",
                    row["device_type"],
                    row["host"],
                )
                continue
            devices.append(row)
    return devices


def extract_version(output: str, device_type: str) -> Optional[str]:
    pattern = VERSION_PATTERNS.get(device_type)
    if not pattern:
        return None
    match = re.search(pattern, output, re.IGNORECASE | re.DOTALL)
    return match.group(1) if match else None


def versions_compliant(current: str, minimum: str) -> bool:
    """Compare versions numerically; fall back to exact string match."""
    def to_ints(v: str) -> tuple:
        return tuple(int(x) for x in re.findall(r"\d+", v))

    try:
        return to_ints(current) >= to_ints(minimum)
    except (ValueError, TypeError):
        return current == minimum


def check_device(host: str, device_type: str, min_version: str,
                 username: str, password: str, timeout: int) -> dict:
    result = {
        "host": host,
        "device_type": device_type,
        "min_version": min_version,
        "current_version": "N/A",
        "status": "ERROR",
        "detail": "",
    }
    try:
        logging.debug("Connecting to %s (%s)", host, device_type)
        with ConnectHandler(
            device_type=device_type,
            host=host,
            username=username,
            password=password,
            timeout=timeout,
        ) as conn:
            output = conn.send_command(VERSION_COMMANDS[device_type])
            logging.debug("Output from %s:\n%s", host, output)

            current = extract_version(output, device_type)
            if not current:
                result["detail"] = "Version string not found in output"
                return result

            result["current_version"] = current
            if versions_compliant(current, min_version):
                result["status"] = "PASS"
                result["detail"] = f"{current} >= {min_version}"
            else:
                result["status"] = "FAIL"
                result["detail"] = f"{current} < {min_version} — upgrade required"

    except NetmikoAuthenticationException:
        result["detail"] = "Authentication failed"
        logging.error("Auth failure on %s", host)
    except NetmikoTimeoutException:
        result["detail"] = "Connection timed out"
        logging.error("Timeout on %s", host)
    except Exception as exc:
        result["detail"] = str(exc)
        logging.error("Error on %s: %s", host, exc)

    return result


def print_summary(results: list) -> None:
    counts = {"PASS": 0, "FAIL": 0, "ERROR": 0}
    print("\n" + "=" * 68)
    print(f"{'HOST':<20} {'STATUS':<8} {'CURRENT':<18} DETAIL")
    print("-" * 68)
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
        print(
            f"{r['host']:<20} {r['status']:<8} {r['current_version']:<18} {r['detail']}"
        )
    print("=" * 68)
    print(f"PASS: {counts['PASS']}  FAIL: {counts['FAIL']}  ERROR: {counts['ERROR']}")
    print("=" * 68 + "\n")


def write_report(results: list, path: str) -> None:
    fields = ["host", "device_type", "min_version", "current_version", "status", "detail"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)
    logging.info("Report saved to %s", path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit network devices against a minimum firmware version baseline."
    )
    parser.add_argument("--inventory", required=True,
                        help="CSV file: host,device_type,min_version")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument("--output", default=None,
                        help="Write compliance results to this CSV file")
    parser.add_argument("--timeout", type=int, default=30,
                        help="SSH timeout in seconds (default: 30)")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable debug-level logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    setup_logging(args.verbose)

    try:
        inventory = load_inventory(args.inventory)
    except (FileNotFoundError, ValueError) as exc:
        logging.error("Inventory error: %s", exc)
        sys.exit(1)

    if not inventory:
        logging.error("No valid devices found in inventory.")
        sys.exit(1)

    logging.info("Auditing %d device(s) against firmware baseline...", len(inventory))

    results = []
    for device in inventory:
        logging.info("Checking %s...", device["host"])
        results.append(check_device(
            host=device["host"],
            device_type=device["device_type"],
            min_version=device["min_version"],
            username=args.username,
            password=args.password,
            timeout=args.timeout,
        ))

    print_summary(results)

    if args.output:
        write_report(results, args.output)

    non_passing = sum(1 for r in results if r["status"] != "PASS")
    sys.exit(0 if non_passing == 0 else 1)
```