```python
"""
firmware_compliance_audit.py — Batch firmware compliance checker for network devices.

Connects to multiple devices from an inventory file, retrieves running firmware
versions, and compares them against a policy baseline. Outputs a pass/fail
compliance report in text or JSON format.

Usage:
    python firmware_compliance_audit.py --inventory devices.json [--output report.json]

Inventory file format (JSON):
    [
      {
        "host": "192.168.1.1",
        "device_type": "cisco_ios",
        "username": "admin",
        "password": "secret",
        "expected_version": "15.2(7)E4"
      }
    ]

Prerequisites:
    pip install netmiko
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

VERSION_COMMANDS = {
    "cisco_ios": "show version",
    "cisco_xe": "show version",
    "cisco_nxos": "show version",
    "cisco_xr": "show version",
    "arista_eos": "show version",
    "juniper_junos": "show version",
}

VERSION_PATTERNS = {
    "cisco_ios": r"Cisco IOS Software.*Version\s+([\S]+),",
    "cisco_xe": r"Cisco IOS XE Software.*Version\s+([\S]+)",
    "cisco_nxos": r"NXOS:\s+version\s+([\S]+)",
    "cisco_xr": r"Cisco IOS XR Software.*Version\s+([\S]+)",
    "arista_eos": r"EOS version:\s+([\S]+)",
    "juniper_junos": r"Junos:\s+([\S]+)",
}


def get_firmware_version(connection, device_type):
    cmd = VERSION_COMMANDS.get(device_type)
    if not cmd:
        raise ValueError(f"Unsupported device type: {device_type}")

    output = connection.send_command(cmd)
    pattern = VERSION_PATTERNS.get(device_type)
    if not pattern:
        return None

    match = re.search(pattern, output, re.IGNORECASE)
    return match.group(1) if match else None


def audit_device(device):
    host = device["host"]
    expected = device.get("expected_version", "").strip()
    device_type = device.get("device_type", "cisco_ios")

    result = {
        "host": host,
        "device_type": device_type,
        "expected_version": expected,
        "actual_version": None,
        "compliant": False,
        "error": None,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    conn_params = {
        "host": host,
        "device_type": device_type,
        "username": device.get("username"),
        "password": device.get("password"),
        "secret": device.get("secret", ""),
        "port": device.get("port", 22),
        "timeout": device.get("timeout", 30),
    }

    try:
        logger.info("Connecting to %s (%s)", host, device_type)
        with ConnectHandler(**conn_params) as conn:
            actual = get_firmware_version(conn, device_type)
            result["actual_version"] = actual

            if actual is None:
                result["error"] = "Could not parse firmware version from output"
            elif not expected:
                result["error"] = "No expected_version specified in inventory"
            else:
                result["compliant"] = actual.strip() == expected

        status = "COMPLIANT" if result["compliant"] else "NON-COMPLIANT"
        logger.info(
            "%s — %s (actual=%s, expected=%s)",
            host, status, result["actual_version"], expected,
        )

    except AuthenticationException:
        result["error"] = "Authentication failed"
        logger.error("%s — authentication failed", host)
    except NetmikoTimeoutException:
        result["error"] = "Connection timed out"
        logger.error("%s — connection timed out", host)
    except Exception as exc:
        result["error"] = str(exc)
        logger.error("%s — %s", host, exc)

    return result


def print_text_report(results):
    print("\n" + "=" * 60)
    print("FIRMWARE COMPLIANCE AUDIT REPORT")
    print("=" * 60)
    compliant = sum(1 for r in results if r["compliant"])
    total = len(results)

    for r in results:
        status = "PASS" if r["compliant"] else "FAIL"
        print(f"\n[{status}] {r['host']} ({r['device_type']})")
        print(f"  Expected : {r['expected_version'] or 'N/A'}")
        print(f"  Actual   : {r['actual_version'] or 'N/A'}")
        if r["error"]:
            print(f"  Error    : {r['error']}")

    print("\n" + "-" * 60)
    print(f"Result: {compliant}/{total} devices compliant")
    print("=" * 60 + "\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Audit firmware compliance across network devices"
    )
    parser.add_argument(
        "--inventory", required=True,
        help="Path to JSON inventory file"
    )
    parser.add_argument(
        "--output",
        help="Write JSON report to this file (optional)"
    )
    parser.add_argument(
        "--fail-on-noncompliant", action="store_true",
        help="Exit with code 1 if any device is non-compliant"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    try:
        with open(args.inventory) as f:
            inventory = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        logger.error("Failed to load inventory: %s", exc)
        sys.exit(2)

    if not inventory:
        logger.error("Inventory is empty")
        sys.exit(2)

    results = [audit_device(device) for device in inventory]

    print_text_report(results)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        logger.info("JSON report written to %s", args.output)

    if args.fail_on_noncompliant and any(not r["compliant"] for r in results):
        sys.exit(1)
```