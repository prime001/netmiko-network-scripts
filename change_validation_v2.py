```python
"""
Pre/Post Change Snapshot Diff Validator
========================================
Captures a device state snapshot before a maintenance window, then compares
it against the live device after changes are applied to surface regressions.

Usage:
    # Capture pre-change baseline
    python 034_pre_post_change_diff.py --host 10.0.0.1 --username admin \
        --password secret --mode snapshot --output pre_change.json

    # Validate post-change state against baseline
    python 034_pre_post_change_diff.py --host 10.0.0.1 --username admin \
        --password secret --mode diff --baseline pre_change.json

Prerequisites:
    pip install netmiko
    Tested against Cisco IOS / IOS-XE. Adjust commands for other vendors.
"""

import argparse
import json
import logging
import sys
from datetime import datetime

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

SNAPSHOT_COMMANDS = [
    "show ip interface brief",
    "show ip bgp summary",
    "show ip route summary",
    "show spanning-tree summary",
    "show interfaces status",
    "show cdp neighbors",
]


def connect(host, username, password, device_type, port):
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "timeout": 30,
        "session_log": None,
    }
    try:
        conn = ConnectHandler(**params)
        log.info("Connected to %s", host)
        return conn
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Timed out connecting to %s", host)
        sys.exit(1)


def capture_snapshot(conn, host):
    snapshot = {
        "host": host,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "commands": {},
    }
    for cmd in SNAPSHOT_COMMANDS:
        log.info("Running: %s", cmd)
        try:
            output = conn.send_command(cmd, read_timeout=20)
            snapshot["commands"][cmd] = output
        except Exception as exc:
            log.warning("Command failed (%s): %s", cmd, exc)
            snapshot["commands"][cmd] = f"ERROR: {exc}"
    return snapshot


def write_snapshot(snapshot, path):
    with open(path, "w") as fh:
        json.dump(snapshot, fh, indent=2)
    log.info("Snapshot saved to %s", path)


def load_snapshot(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        log.error("Baseline file not found: %s", path)
        sys.exit(1)


def diff_snapshots(before, after):
    issues = []
    for cmd in SNAPSHOT_COMMANDS:
        pre = before["commands"].get(cmd, "")
        post = after["commands"].get(cmd, "")
        if pre == post:
            continue
        pre_lines = set(pre.splitlines())
        post_lines = set(post.splitlines())
        removed = pre_lines - post_lines
        added = post_lines - pre_lines
        if removed or added:
            issues.append({
                "command": cmd,
                "removed": sorted(removed),
                "added": sorted(added),
            })
    return issues


def print_diff_report(before, after, issues):
    print("\n" + "=" * 60)
    print(f"  Change Validation Report")
    print(f"  Host    : {after['host']}")
    print(f"  Before  : {before['timestamp']}")
    print(f"  After   : {after['timestamp']}")
    print("=" * 60)
    if not issues:
        print("  PASS — no differences detected\n")
        return True
    print(f"  FAIL — {len(issues)} command(s) show differences\n")
    for issue in issues:
        print(f"  [{issue['command']}]")
        for line in issue["removed"]:
            if line.strip():
                print(f"    - {line}")
        for line in issue["added"]:
            if line.strip():
                print(f"    + {line}")
        print()
    return False


def parse_args():
    p = argparse.ArgumentParser(description="Pre/post change snapshot diff for network devices")
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("--username", required=True, help="SSH username")
    p.add_argument("--password", required=True, help="SSH password")
    p.add_argument("--device-type", default="cisco_ios", help="Netmiko device type (default: cisco_ios)")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--mode", required=True, choices=["snapshot", "diff"],
                   help="snapshot: capture baseline; diff: compare against baseline")
    p.add_argument("--output", default="snapshot.json", help="Output file for snapshot mode")
    p.add_argument("--baseline", help="Baseline JSON file for diff mode")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.mode == "diff" and not args.baseline:
        log.error("--baseline is required for diff mode")
        sys.exit(1)

    conn = connect(args.host, args.username, args.password, args.device_type, args.port)
    try:
        current = capture_snapshot(conn, args.host)
    finally:
        conn.disconnect()

    if args.mode == "snapshot":
        write_snapshot(current, args.output)
        log.info("Snapshot complete.")
        sys.exit(0)

    baseline = load_snapshot(args.baseline)
    issues = diff_snapshots(baseline, current)
    passed = print_diff_report(baseline, current, issues)
    sys.exit(0 if passed else 2)
```