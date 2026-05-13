```python
"""
interface_snapshot.py — Pre/post-change interface state comparator.

Captures a baseline snapshot of interface error counters and operational status,
then compares a fresh reading against that baseline to surface drift introduced
during a maintenance window.

Usage:
    # Capture baseline before the change:
    python interface_snapshot.py --host 192.168.1.1 --user admin --password secret \
        --snapshot --baseline-file /tmp/pre_change.json

    # Compare current state after the change:
    python interface_snapshot.py --host 192.168.1.1 --user admin --password secret \
        --compare --baseline-file /tmp/pre_change.json

    Exit code 0 = no drift; exit code 1 = drift detected or error.

Prerequisites:
    pip install netmiko
    Device must support 'show interfaces' (Cisco IOS/IOS-XE/NX-OS).
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

COUNTER_FIELDS = ("input_errors", "output_errors", "crc", "resets")


def parse_interfaces(raw: str) -> dict:
    """Return per-interface state and counters parsed from 'show interfaces'."""
    interfaces = {}
    current = None

    for line in raw.splitlines():
        header = re.match(r'^(\S+)\s+is\s+(administratively\s+down|up|down)', line, re.IGNORECASE)
        if header:
            current = header.group(1)
            admin_down = "administratively" in line.lower()
            oper_up = line.lower().split(" is ")[-1].strip().startswith("up")
            interfaces[current] = {
                "admin": "down" if admin_down else "up",
                "oper": "up" if oper_up else "down",
                "input_errors": 0,
                "output_errors": 0,
                "crc": 0,
                "resets": 0,
            }
            continue

        if current is None:
            continue

        for pattern, field in (
            (r"(\d+)\s+input errors", "input_errors"),
            (r"(\d+)\s+output errors", "output_errors"),
            (r"(\d+)\s+CRC", "crc"),
            (r"(\d+)\s+interface resets", "resets"),
        ):
            m = re.search(pattern, line, re.IGNORECASE)
            if m:
                interfaces[current][field] = int(m.group(1))

    return interfaces


def capture_snapshot(conn, baseline_path: Path) -> None:
    """Write current interface state to a JSON baseline file."""
    log.info("Collecting interface data from %s...", conn.host)
    raw = conn.send_command("show interfaces", read_timeout=60)
    interfaces = parse_interfaces(raw)
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": conn.host,
        "interfaces": interfaces,
    }
    baseline_path.write_text(json.dumps(payload, indent=2))
    log.info("Snapshot saved to %s (%d interfaces)", baseline_path, len(interfaces))


def compare_snapshot(conn, baseline_path: Path) -> bool:
    """Compare current interface state to a saved baseline. Returns True if clean."""
    if not baseline_path.exists():
        log.error("Baseline file not found: %s", baseline_path)
        return False

    baseline = json.loads(baseline_path.read_text())
    log.info(
        "Loaded baseline for %s captured at %s",
        baseline["host"],
        baseline["timestamp"],
    )

    log.info("Collecting current interface data from %s...", conn.host)
    raw = conn.send_command("show interfaces", read_timeout=60)
    current = parse_interfaces(raw)

    diffs = []

    for iface, now in current.items():
        pre = baseline["interfaces"].get(iface)
        if pre is None:
            diffs.append(f"  NEW   {iface}  (not present in baseline)")
            continue

        if pre["admin"] != now["admin"]:
            diffs.append(f"  ADMIN {iface}: {pre['admin']} -> {now['admin']}")
        if pre["oper"] != now["oper"]:
            diffs.append(f"  OPER  {iface}: {pre['oper']} -> {now['oper']}")

        for field in COUNTER_FIELDS:
            delta = now[field] - pre.get(field, 0)
            if delta > 0:
                diffs.append(f"  {field.upper():<20s} {iface}: +{delta}")

    for iface in baseline["interfaces"]:
        if iface not in current:
            diffs.append(f"  GONE  {iface}  (was in baseline, not seen now)")

    if diffs:
        print(f"\nDrift detected — {len(diffs)} difference(s) found:")
        for line in diffs:
            print(line)
        return False

    print(f"\nClean — {len(current)} interfaces match baseline, no drift detected.")
    return True


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture and compare interface state around a maintenance window.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type",
    )
    parser.add_argument(
        "--baseline-file", default="interface_baseline.json",
        help="Path to baseline JSON file",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--snapshot", action="store_true", help="Capture baseline snapshot")
    mode.add_argument("--compare", action="store_true", help="Compare current state to baseline")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()

    device_params = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.user,
        "password": args.password,
    }

    try:
        log.info("Connecting to %s...", args.host)
        with ConnectHandler(**device_params) as conn:
            baseline_path = Path(args.baseline_file)
            if args.snapshot:
                capture_snapshot(conn, baseline_path)
            else:
                clean = compare_snapshot(conn, baseline_path)
                sys.exit(0 if clean else 1)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        sys.exit(1)
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        sys.exit(1)
```