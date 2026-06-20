firmware_compliance.py - Network Device Firmware Compliance Reporter

Purpose:
    Compares running firmware versions on network devices against a required-version
    policy file. Produces a per-device compliance report and optional CSV export.
    Useful for audits, change-freeze enforcement, and CVE remediation tracking.

Usage:
    python firmware_compliance.py --host 192.168.1.1 --device-type cisco_ios \
        --username admin --password secret --policy policy.yaml

    python firmware_compliance.py --host-file hosts.txt --policy policy.yaml \
        --output compliance_report.csv

Policy file format (YAML):
    cisco_ios:
      required: "15.9(3)M6"
    cisco_nxos:
      required: "9.3(8)"
    arista_eos:
      required: "4.28.3M"

hosts.txt format (one entry per line):
    192.168.1.1:cisco_ios
    192.168.1.2:cisco_nxos

Prerequisites:
    pip install netmiko pyyaml
"""

import argparse
import csv
import logging
import sys
from dataclasses import dataclass
from typing import Optional

import yaml
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

VERSION_COMMANDS = {
    "cisco_ios": "show version | include Version",
    "cisco_nxos": "show version | include NXOS",
    "cisco_xr": "show version | include Version",
    "juniper_junos": "show version | match Junos",
    "arista_eos": "show version | include Software image version",
}


@dataclass
class DeviceResult:
    host: str
    device_type: str
    running_version: Optional[str] = None
    required_version: Optional[str] = None
    status: str = "UNKNOWN"
    error: Optional[str] = None


def get_running_version(host: str, device_type: str, username: str, password: str,
                        port: int = 22, secret: str = "") -> Optional[str]:
    cmd = VERSION_COMMANDS.get(device_type)
    if not cmd:
        raise ValueError(f"Unsupported device type: {device_type}")

    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "secret": secret or password,
        "timeout": 30,
    }
    with ConnectHandler(**device) as conn:
        output = conn.send_command(cmd)

    version_line = output.strip().splitlines()[0] if output.strip() else ""
    for delimiter in ("Version ", "version ", ": "):
        if delimiter in version_line:
            return version_line.split(delimiter)[-1].split()[0].rstrip(",")
    return version_line or None


def load_policy(policy_file: str) -> dict:
    with open(policy_file) as f:
        return yaml.safe_load(f) or {}


def check_device(host: str, device_type: str, username: str, password: str,
                 policy: dict, port: int = 22, secret: str = "") -> DeviceResult:
    result = DeviceResult(host=host, device_type=device_type)
    policy_entry = policy.get(device_type, {})
    result.required_version = policy_entry.get("required")

    try:
        result.running_version = get_running_version(
            host, device_type, username, password, port, secret
        )
    except NetmikoAuthenticationException:
        result.status = "AUTH_FAILED"
        result.error = "Authentication failed"
        log.error("%s: authentication failed", host)
        return result
    except NetmikoTimeoutException:
        result.status = "TIMEOUT"
        result.error = "Connection timed out"
        log.error("%s: connection timed out", host)
        return result
    except Exception as exc:
        result.status = "ERROR"
        result.error = str(exc)
        log.error("%s: %s", host, exc)
        return result

    if not result.required_version:
        result.status = "NO_POLICY"
        log.warning("%s: no policy defined for %s", host, device_type)
    elif result.running_version == result.required_version:
        result.status = "COMPLIANT"
        log.info("%s: COMPLIANT (%s)", host, result.running_version)
    else:
        result.status = "NON_COMPLIANT"
        log.warning(
            "%s: NON_COMPLIANT — running %s, required %s",
            host, result.running_version, result.required_version,
        )
    return result


def print_summary(results: list) -> None:
    compliant = sum(1 for r in results if r.status == "COMPLIANT")
    non_compliant = sum(1 for r in results if r.status == "NON_COMPLIANT")
    errors = sum(1 for r in results if r.status in ("AUTH_FAILED", "TIMEOUT", "ERROR"))
    no_policy = len(results) - compliant - non_compliant - errors

    print(f"\n{'=' * 60}")
    print("Firmware Compliance Summary")
    print(f"{'=' * 60}")
    print(f"  Total devices : {len(results)}")
    print(f"  Compliant     : {compliant}")
    print(f"  Non-compliant : {non_compliant}")
    print(f"  Errors        : {errors}")
    print(f"  No policy     : {no_policy}")
    print(f"{'=' * 60}")

    markers = {"COMPLIANT": "OK", "NON_COMPLIANT": "!!", "NO_POLICY": "--"}
    for r in results:
        marker = markers.get(r.status, "XX")
        ver_info = f"{r.running_version or 'N/A'} (required: {r.required_version or 'N/A'})"
        print(f"  [{marker}] {r.host:<20} {r.status:<14} {ver_info}")
    print()


def write_csv(results: list, path: str) -> None:
    fields = ["host", "device_type", "running_version", "required_version", "status", "error"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "host": r.host,
                "device_type": r.device_type,
                "running_version": r.running_version or "",
                "required_version": r.required_version or "",
                "status": r.status,
                "error": r.error or "",
            })
    log.info("Report written to %s", path)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Check network device firmware versions against a compliance policy."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="Single device IP or hostname")
    group.add_argument("--host-file", help="File with one host:device_type per line")
    parser.add_argument("--device-type", help="Netmiko device type (required with --host)")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--secret", default="", help="Enable secret")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--policy", required=True, help="YAML policy file")
    parser.add_argument("--output", help="Write results to CSV file")
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.host and not args.device_type:
        print("ERROR: --device-type is required when using --host", file=sys.stderr)
        sys.exit(1)

    policy = load_policy(args.policy)

    targets = []
    if args.host:
        targets = [(args.host, args.device_type)]
    else:
        with open(args.host_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":", 1)
                if len(parts) != 2:
                    log.warning("Skipping malformed line: %s", line)
                    continue
                targets.append((parts[0].strip(), parts[1].strip()))

    results = []
    for host, device_type in targets:
        result = check_device(
            host, device_type, args.username, args.password,
            policy, args.port, args.secret,
        )
        results.append(result)

    print_summary(results)

    if args.output:
        write_csv(results, args.output)

    sys.exit(1 if any(r.status == "NON_COMPLIANT" for r in results) else 0)