```python
"""
interface_error_monitor.py - Interface error counter monitor with snapshot comparison.

Purpose:
    Connects to a network device, collects interface error counters, and flags
    interfaces exceeding configurable thresholds. Supports before/after change
    snapshots to detect errors introduced by configuration changes.

Usage:
    # Report current error counts against thresholds:
    python interface_error_monitor.py --host 192.168.1.1 -u admin -p secret

    # Save pre-change baseline snapshot:
    python interface_error_monitor.py --host 192.168.1.1 -u admin -p secret --save-snapshot pre.json

    # Compare post-change counters against baseline:
    python interface_error_monitor.py --host 192.168.1.1 -u admin -p secret --compare-snapshot pre.json

Prerequisites:
    pip install netmiko
    Tested against Cisco IOS and IOS-XE. Adjust regex patterns for other vendors.
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

COUNTER_FIELDS = ["input errors", "output errors", "CRC", "runts", "giants", "resets"]

DEFAULT_THRESHOLDS = {
    "input errors": 100,
    "output errors": 100,
    "CRC": 50,
    "runts": 50,
    "giants": 10,
    "resets": 5,
}


def parse_interface_counters(raw_output: str) -> dict:
    """Parse 'show interfaces' output into {iface: {counter: value}}."""
    interfaces = {}
    current_iface = None

    for line in raw_output.splitlines():
        iface_match = re.match(r'^(\S+)\s+is\s+\w+', line)
        if iface_match:
            current_iface = iface_match.group(1)
            interfaces[current_iface] = {}
            continue

        if current_iface is None:
            continue

        for field in COUNTER_FIELDS:
            match = re.search(rf'(\d+)\s+{re.escape(field)}', line, re.IGNORECASE)
            if match:
                interfaces[current_iface][field] = int(match.group(1))

    return interfaces


def collect_counters(host: str, username: str, password: str, device_type: str) -> dict:
    """Connect to device and return parsed interface counters."""
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "timeout": 30,
    }
    log.info("Connecting to %s (%s)", host, device_type)
    with ConnectHandler(**device) as conn:
        output = conn.send_command("show interfaces")
    return parse_interface_counters(output)


def check_thresholds(counters: dict, thresholds: dict) -> list:
    """Return list of (iface, field, value, limit) tuples exceeding thresholds."""
    violations = []
    for iface, fields in counters.items():
        for field, value in fields.items():
            limit = thresholds.get(field)
            if limit is not None and value > limit:
                violations.append((iface, field, value, limit))
    return violations


def compute_deltas(baseline: dict, current: dict) -> dict:
    """Return non-zero counter deltas between two snapshots."""
    deltas = {}
    for iface in current:
        if iface not in baseline:
            continue
        iface_deltas = {
            field: current[iface][field] - baseline[iface].get(field, 0)
            for field in current[iface]
            if current[iface][field] - baseline[iface].get(field, 0) != 0
        }
        if iface_deltas:
            deltas[iface] = iface_deltas
    return deltas


def print_report(violations: list, deltas: dict = None) -> None:
    """Print formatted counter report."""
    if deltas is not None:
        print("\n=== Interface Counter Deltas (since snapshot) ===")
        if not deltas:
            print("  No counter changes detected.")
        for iface, fields in deltas.items():
            print(f"  {iface}:")
            for field, delta in fields.items():
                marker = " [INCREASED]" if delta > 0 else ""
                print(f"    {field}: {delta:+,}{marker}")

    print("\n=== Threshold Violations ===")
    if not violations:
        print("  No violations detected.")
        return
    for iface, field, value, limit in sorted(violations):
        print(f"  [FAIL] {iface}: {field} = {value:,}  (threshold: {limit:,})")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor interface error counters; compare pre/post change snapshots."
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--username", "-u", required=True, help="SSH username")
    parser.add_argument("--password", "-p", required=True, help="SSH password")
    parser.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument(
        "--save-snapshot", metavar="FILE",
        help="Save current counters to JSON file as a pre-change baseline",
    )
    parser.add_argument(
        "--compare-snapshot", metavar="FILE",
        help="Compare current counters against a previously saved snapshot",
    )
    parser.add_argument(
        "--threshold-errors", type=int, default=DEFAULT_THRESHOLDS["input errors"],
        help="Input/output error threshold (default: 100)",
    )
    parser.add_argument(
        "--threshold-crc", type=int, default=DEFAULT_THRESHOLDS["CRC"],
        help="CRC error threshold (default: 50)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    thresholds = dict(DEFAULT_THRESHOLDS)
    thresholds["input errors"] = args.threshold_errors
    thresholds["output errors"] = args.threshold_errors
    thresholds["CRC"] = args.threshold_crc

    try:
        counters = collect_counters(
            args.host, args.username, args.password, args.device_type
        )
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        sys.exit(1)
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        sys.exit(1)

    log.info("Collected counters for %d interfaces", len(counters))

    if args.save_snapshot:
        snapshot = {
            "timestamp": datetime.utcnow().isoformat(),
            "host": args.host,
            "counters": counters,
        }
        with open(args.save_snapshot, "w") as fh:
            json.dump(snapshot, fh, indent=2)
        log.info("Snapshot saved to %s", args.save_snapshot)

    deltas = None
    if args.compare_snapshot:
        with open(args.compare_snapshot) as fh:
            baseline_data = json.load(fh)
        log.info(
            "Loaded baseline from %s (captured %s)",
            args.compare_snapshot,
            baseline_data.get("timestamp", "unknown"),
        )
        deltas = compute_deltas(baseline_data["counters"], counters)

    violations = check_thresholds(counters, thresholds)
    print_report(violations, deltas)

    sys.exit(1 if violations else 0)


if __name__ == "__main__":
    main()
```