pre_post_snapshot.py - Pre/Post Change State Capture and Comparison

Purpose:
    Captures key device state metrics (interface status, routing neighbor
    counts, CPU/memory) to a JSON snapshot file before and after a
    maintenance window, then diffs two snapshots to surface unintended
    changes introduced during the change.

Usage:
    # Capture pre-change baseline
    python pre_post_snapshot.py --host 192.168.1.1 --username admin \
        --password secret --device-type cisco_ios --mode capture \
        --snapshot-file pre_change.json

    # After the change, capture post-change state
    python pre_post_snapshot.py --host 192.168.1.1 --username admin \
        --password secret --device-type cisco_ios --mode capture \
        --snapshot-file post_change.json

    # Compare the two snapshots
    python pre_post_snapshot.py --mode diff \
        --before pre_change.json --after post_change.json

Prerequisites:
    pip install netmiko
    Python 3.8+
    SSH access to target device with enable privileges
"""

import argparse
import json
import logging
import sys
from datetime import datetime

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

CAPTURE_COMMANDS = {
    "cisco_ios": [
        ("interfaces", "show interfaces"),
        ("bgp_summary", "show ip bgp summary"),
        ("ospf_neighbors", "show ip ospf neighbor"),
        ("routes", "show ip route summary"),
        ("cpu", "show processes cpu sorted | head 5"),
        ("memory", "show processes memory sorted | head 5"),
    ],
    "cisco_xe": [
        ("interfaces", "show interfaces"),
        ("bgp_summary", "show ip bgp summary"),
        ("ospf_neighbors", "show ip ospf neighbor"),
        ("routes", "show ip route summary"),
        ("cpu", "show processes cpu sorted | head 5"),
        ("memory", "show processes memory sorted | head 5"),
    ],
    "cisco_nxos": [
        ("interfaces", "show interface status"),
        ("bgp_summary", "show bgp summary"),
        ("ospf_neighbors", "show ip ospf neighbors"),
        ("routes", "show ip route summary"),
        ("cpu", "show system resources"),
        ("memory", "show system resources"),
    ],
    "arista_eos": [
        ("interfaces", "show interfaces status"),
        ("bgp_summary", "show bgp summary"),
        ("ospf_neighbors", "show ip ospf neighbor"),
        ("routes", "show ip route summary"),
        ("cpu", "show processes top once"),
        ("memory", "show version | grep Memory"),
    ],
}


def capture_snapshot(host, username, password, device_type, port=22):
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
    }

    commands = CAPTURE_COMMANDS.get(device_type, CAPTURE_COMMANDS["cisco_ios"])
    snapshot = {
        "host": host,
        "device_type": device_type,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "data": {},
    }

    try:
        log.info("Connecting to %s", host)
        with ConnectHandler(**device) as conn:
            conn.enable()
            for key, cmd in commands:
                log.info("Running: %s", cmd)
                try:
                    snapshot["data"][key] = conn.send_command(cmd)
                except Exception as exc:
                    log.warning("Command '%s' failed: %s", cmd, exc)
                    snapshot["data"][key] = ""
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", host)
        sys.exit(1)

    return snapshot


def diff_snapshots(before_file, after_file):
    with open(before_file) as f:
        before = json.load(f)
    with open(after_file) as f:
        after = json.load(f)

    print(f"\n{'=' * 60}")
    print(f"Pre-change:  {before['timestamp']}  ({before['host']})")
    print(f"Post-change: {after['timestamp']}  ({after['host']})")
    print(f"{'=' * 60}\n")

    changes_found = False
    for key in before["data"]:
        before_val = before["data"].get(key, "").strip()
        after_val = after["data"].get(key, "").strip()
        if before_val == after_val:
            print(f"[OK]      {key}")
            continue

        changes_found = True
        print(f"[CHANGED] {key}")
        before_lines = set(before_val.splitlines())
        after_lines = set(after_val.splitlines())
        for line in sorted(before_lines - after_lines):
            print(f"  - {line}")
        for line in sorted(after_lines - before_lines):
            print(f"  + {line}")
        print()

    print()
    if not changes_found:
        print("Result: No differences detected between snapshots.")
    else:
        print("Result: Differences found. Review lines prefixed with '-' (removed) and '+' (added).")


def main():
    parser = argparse.ArgumentParser(
        description="Capture and compare device state snapshots for change validation."
    )
    parser.add_argument(
        "--mode",
        choices=["capture", "diff"],
        required=True,
        help="'capture' saves current device state; 'diff' compares two snapshot files",
    )
    parser.add_argument("--host", help="Device IP or hostname (required for capture)")
    parser.add_argument("--username", help="SSH username (required for capture)")
    parser.add_argument("--password", help="SSH password (required for capture)")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(CAPTURE_COMMANDS.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--snapshot-file",
        help="JSON file to write captured snapshot to (capture mode)",
    )
    parser.add_argument("--before", help="Pre-change snapshot JSON file (diff mode)")
    parser.add_argument("--after", help="Post-change snapshot JSON file (diff mode)")

    args = parser.parse_args()

    if args.mode == "capture":
        if not all([args.host, args.username, args.password, args.snapshot_file]):
            parser.error(
                "capture mode requires --host, --username, --password, --snapshot-file"
            )
        snapshot = capture_snapshot(
            args.host, args.username, args.password, args.device_type, args.port
        )
        with open(args.snapshot_file, "w") as f:
            json.dump(snapshot, f, indent=2)
        log.info("Snapshot saved to %s", args.snapshot_file)

    elif args.mode == "diff":
        if not args.before or not args.after:
            parser.error("diff mode requires --before and --after snapshot file paths")
        diff_snapshots(args.before, args.after)


if __name__ == "__main__":
    main()