```python
"""
firmware_compliance_audit.py — Multi-device firmware compliance auditor.

Reads a device inventory (CSV) and a firmware policy file (JSON), connects
to each device via Netmiko, retrieves the running software version, and
produces a compliance report showing which devices are on approved firmware.

Usage:
    python firmware_compliance_audit.py \\
        --inventory devices.csv \\
        --policy policy.json \\
        --username admin \\
        --password secret \\
        --output report.csv

Prerequisites:
    pip install netmiko

Inventory CSV format (header required):
    hostname,ip,device_type
    core-sw-01,10.0.0.1,cisco_ios
    edge-rtr-01,10.0.0.2,cisco_ios

Policy JSON format:
    {
      "cisco_ios": ["15.9(3)M6", "16.9.8", "17.6.5"],
      "cisco_nxos": ["9.3(10)", "10.2(5)"]
    }
"""

import argparse
import csv
import json
import logging
import sys
from datetime import datetime
from typing import Optional

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

VERSION_COMMANDS = {
    "cisco_ios": "show version",
    "cisco_nxos": "show version",
    "cisco_iosxe": "show version",
    "arista_eos": "show version",
    "juniper_junos": "show version",
}

VERSION_PATTERNS = {
    "cisco_ios": "Cisco IOS Software.*Version ([\\d.()A-Za-z]+)",
    "cisco_iosxe": "Cisco IOS XE Software.*Version ([\\d.()A-Za-z]+)",
    "cisco_nxos": "NXOS: version ([\\d.()A-Za-z]+)",
    "arista_eos": "EOS version ([\\d.A-Za-z]+)",
    "juniper_junos": "Junos: ([\\d.A-Za-z]+)",
}


def load_inventory(path: str) -> list[dict]:
    devices = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            required = {"hostname", "ip", "device_type"}
            if not required.issubset(row.keys()):
                raise ValueError(f"Inventory missing columns: {required - row.keys()}")
            devices.append(row)
    return devices


def load_policy(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def get_running_version(host: str, ip: str, device_type: str,
                         username: str, password: str,
                         secret: Optional[str], timeout: int) -> Optional[str]:
    import re

    cmd = VERSION_COMMANDS.get(device_type)
    if not cmd:
        log.warning("%s: unsupported device_type '%s'", host, device_type)
        return None

    params = {
        "device_type": device_type,
        "host": ip,
        "username": username,
        "password": password,
        "timeout": timeout,
    }
    if secret:
        params["secret"] = secret

    try:
        with ConnectHandler(**params) as conn:
            if secret:
                conn.enable()
            output = conn.send_command(cmd)
    except NetmikoAuthenticationException:
        log.error("%s (%s): authentication failed", host, ip)
        return None
    except NetmikoTimeoutException:
        log.error("%s (%s): connection timed out", host, ip)
        return None
    except Exception as exc:
        log.error("%s (%s): %s", host, ip, exc)
        return None

    pattern = VERSION_PATTERNS.get(device_type, r"Version ([\\d.()A-Za-z]+)")
    match = re.search(pattern, output, re.IGNORECASE)
    if match:
        return match.group(1)

    log.warning("%s: could not parse version from output", host)
    return None


def audit_devices(devices: list[dict], policy: dict,
                   username: str, password: str,
                   secret: Optional[str], timeout: int) -> list[dict]:
    results = []
    for dev in devices:
        hostname = dev["hostname"]
        ip = dev["ip"]
        device_type = dev["device_type"]

        log.info("Checking %s (%s) ...", hostname, ip)
        version = get_running_version(hostname, ip, device_type, username, password, secret, timeout)

        approved = policy.get(device_type, [])
        if version is None:
            status = "ERROR"
        elif not approved:
            status = "NO_POLICY"
        elif version in approved:
            status = "COMPLIANT"
        else:
            status = "NON_COMPLIANT"

        results.append({
            "hostname": hostname,
            "ip": ip,
            "device_type": device_type,
            "running_version": version or "N/A",
            "approved_versions": ", ".join(approved) if approved else "none defined",
            "status": status,
        })
        log.info("%s: %s (version=%s)", hostname, status, version or "N/A")

    return results


def write_report(results: list[dict], output_path: str) -> None:
    fields = ["hostname", "ip", "device_type", "running_version", "approved_versions", "status"]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)
    log.info("Report written to %s", output_path)


def print_summary(results: list[dict]) -> None:
    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1

    print(f"\n{'='*50}")
    print(f"Firmware Compliance Audit — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*50}")
    print(f"Total devices : {len(results)}")
    for status, count in sorted(counts.items()):
        print(f"  {status:<16}: {count}")
    print(f"{'='*50}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit firmware compliance across a device inventory."
    )
    parser.add_argument("--inventory", required=True, help="Path to CSV inventory file")
    parser.add_argument("--policy", required=True, help="Path to JSON firmware policy file")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument("--secret", default=None, help="Enable secret (optional)")
    parser.add_argument("--output", default="firmware_audit_report.csv", help="Output CSV path")
    parser.add_argument("--timeout", type=int, default=30, help="Connection timeout in seconds")
    args = parser.parse_args()

    try:
        devices = load_inventory(args.inventory)
        policy = load_policy(args.policy)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        log.error("Failed to load input files: %s", exc)
        sys.exit(1)

    log.info("Loaded %d devices, %d policy entries", len(devices), len(policy))

    results = audit_devices(
        devices, policy, args.username, args.password, args.secret, args.timeout
    )

    write_report(results, args.output)
    print_summary(results)

    non_compliant = sum(1 for r in results if r["status"] == "NON_COMPLIANT")
    sys.exit(1 if non_compliant else 0)


if __name__ == "__main__":
    main()
```