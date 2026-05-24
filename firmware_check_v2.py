Writing the firmware audit script now, taking a batch inventory-based compliance angle to differentiate from existing single-device firmware_check variants.

```python
"""
firmware_audit.py - Batch firmware compliance auditor for network devices.

Reads a device inventory CSV, connects to each device via Netmiko, compares
the running OS version against a per-device expected version, and produces a
compliance report in both console table and JSON formats.

Usage:
    python firmware_audit.py --inventory devices.csv
    python firmware_audit.py --inventory devices.csv --output report.json
    python firmware_audit.py --inventory devices.csv --timeout 45 --fail-fast

Inventory CSV columns (required):
    hostname, device_type, ip, username, password, expected_version

Optional CSV column:
    port  (default 22)

Supported device_types:
    cisco_ios, cisco_xe, cisco_nxos, cisco_xr, arista_eos, juniper_junos

Exit code 0 = all devices compliant; 1 = any non-compliant or unreachable.

Prerequisites:
    pip install netmiko
"""

import argparse
import csv
import json
import logging
import re
import sys
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

_VERSION_CMD = {
    "cisco_ios": "show version",
    "cisco_xe": "show version",
    "cisco_nxos": "show version",
    "cisco_xr": "show version",
    "arista_eos": "show version",
    "juniper_junos": "show version",
}

_VERSION_RE = {
    "cisco_ios": r"Version\s+([\d]+\.[\d]+\([^\)]+\)[A-Za-z0-9]*)",
    "cisco_xe": r"Cisco IOS XE Software.*?Version\s+([\d\.]+[A-Za-z0-9\.]*)",
    "cisco_nxos": r"NXOS:\s+version\s+(\S+)",
    "cisco_xr": r"Cisco IOS XR Software.*?Version\s+([\d\.]+)",
    "arista_eos": r"EOS version:\s+([\d\.]+[A-Za-z0-9]*)",
    "juniper_junos": r"Junos:\s+([\d\.A-Za-z]+)",
}


def _extract_version(output: str, device_type: str) -> str | None:
    pattern = _VERSION_RE.get(device_type)
    if not pattern:
        return None
    match = re.search(pattern, output, re.IGNORECASE | re.DOTALL)
    return match.group(1) if match else None


def audit_device(row: dict) -> dict:
    hostname = row["hostname"]
    result = {
        "hostname": hostname,
        "ip": row["ip"],
        "device_type": row["device_type"],
        "expected_version": row["expected_version"],
        "running_version": None,
        "compliant": False,
        "status": "error",
        "error": None,
    }
    params = {
        "device_type": row["device_type"],
        "host": row["ip"],
        "port": int(row.get("port", 22)),
        "username": row["username"],
        "password": row["password"],
        "timeout": int(row.get("_timeout", 30)),
        "fast_cli": False,
    }
    try:
        log.info("Connecting to %s (%s)", hostname, row["ip"])
        with ConnectHandler(**params) as conn:
            cmd = _VERSION_CMD.get(row["device_type"], "show version")
            output = conn.send_command(cmd)
            version = _extract_version(output, row["device_type"])
            result["running_version"] = version
            if version is None:
                result["status"] = "parse_error"
                result["error"] = "Version string not found in output"
                log.warning("%s: could not parse version", hostname)
            elif version.strip() == row["expected_version"].strip():
                result["compliant"] = True
                result["status"] = "compliant"
                log.info("%s: compliant (%s)", hostname, version)
            else:
                result["status"] = "non_compliant"
                log.warning(
                    "%s: NON-COMPLIANT running=%s expected=%s",
                    hostname, version, row["expected_version"],
                )
    except NetmikoAuthenticationException as exc:
        result["status"] = "auth_error"
        result["error"] = str(exc)
        log.error("%s: authentication failed", hostname)
    except NetmikoTimeoutException as exc:
        result["status"] = "timeout"
        result["error"] = str(exc)
        log.error("%s: connection timed out", hostname)
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        log.error("%s: unexpected error: %s", hostname, exc)
    return result


def load_inventory(path: Path, timeout: int) -> list[dict]:
    required = {"hostname", "device_type", "ip", "username", "password", "expected_version"}
    rows = []
    with open(path, newline="") as fh:
        reader = csv.DictReader(fh)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Inventory missing required columns: {missing}")
        for row in reader:
            row["_timeout"] = row.get("timeout", str(timeout))
            rows.append(row)
    return rows


def print_report(results: list[dict]) -> None:
    col = {"hostname": 20, "status": 14, "expected_version": 22, "running_version": 22}
    divider = "-" * sum(col.values())
    print(f"\n{'Firmware Compliance Report':^{len(divider)}}")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(divider)
    header = (
        f"{'HOSTNAME':<{col['hostname']}}"
        f"{'STATUS':<{col['status']}}"
        f"{'EXPECTED':<{col['expected_version']}}"
        f"{'RUNNING':<{col['running_version']}}"
    )
    print(header)
    print(divider)
    for r in results:
        running = r["running_version"] or f"({r['status']})"
        print(
            f"{r['hostname']:<{col['hostname']}}"
            f"{r['status']:<{col['status']}}"
            f"{r['expected_version']:<{col['expected_version']}}"
            f"{running:<{col['running_version']}}"
        )
    print(divider)
    compliant = sum(1 for r in results if r["compliant"])
    print(f"Summary: {compliant}/{len(results)} devices compliant\n")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Audit firmware compliance across a device inventory CSV.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Prerequisites:")[0].strip(),
    )
    p.add_argument("--inventory", required=True, metavar="FILE",
                   help="CSV inventory file (see docstring for format)")
    p.add_argument("--output", metavar="FILE",
                   help="Write full JSON report to this file")
    p.add_argument("--timeout", type=int, default=30, metavar="SEC",
                   help="SSH connect timeout per device (default: 30)")
    p.add_argument("--fail-fast", action="store_true",
                   help="Stop after first non-compliant or unreachable device")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    inventory_path = Path(args.inventory)

    if not inventory_path.exists():
        log.error("Inventory file not found: %s", inventory_path)
        sys.exit(1)

    try:
        devices = load_inventory(inventory_path, args.timeout)
    except ValueError as exc:
        log.error("Invalid inventory: %s", exc)
        sys.exit(1)

    if not devices:
        log.error("No devices found in inventory.")
        sys.exit(1)

    results: list[dict] = []
    for device in devices:
        result = audit_device(device)
        results.append(result)
        if args.fail_fast and not result["compliant"]:
            log.warning("--fail-fast triggered on %s", device["hostname"])
            break

    print_report(results)

    if args.output:
        out_path = Path(args.output)
        report = {
            "generated_at": datetime.now().isoformat(),
            "total": len(results),
            "compliant": sum(1 for r in results if r["compliant"]),
            "results": results,
        }
        out_path.write_text(json.dumps(report, indent=2))
        log.info("JSON report written to %s", out_path)

    sys.exit(0 if all(r["compliant"] for r in results) else 1)
```