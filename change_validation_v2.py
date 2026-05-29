The user wants the script content as text output only — no file write needed. Here it is:

```
route_table_diff.py
```

"""
route_table_diff.py - Pre/post change routing table snapshot and diff tool.

Captures the IPv4 routing table from a Cisco IOS (or compatible) device,
saves a timestamped JSON snapshot, and diffs it against a previously saved
snapshot to surface routes added, removed, or changed during a maintenance
window.

Usage:
    # Capture a pre-change baseline
    python route_table_diff.py --host 10.0.0.1 --username admin --snapshot pre

    # Capture post-change and compare against the pre snapshot
    python route_table_diff.py --host 10.0.0.1 --username admin \
        --snapshot post --compare 10.0.0.1_pre_20240315_143000.json

    # Diff two saved snapshots without connecting to a device
    python route_table_diff.py --diff before.json after.json

Prerequisites:
    pip install netmiko
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime
from getpass import getpass
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

# Matches IOS "show ip route" prefix lines, e.g.:
#   C    10.0.0.0/24 is directly connected, GigabitEthernet0/0
#   O    192.168.1.0/24 [110/2] via 10.0.0.2, 00:01:23, Gi0/0
ROUTE_RE = re.compile(r"^([A-Z*][A-Z* ]*?)\s+([\d./]+)\s+", re.MULTILINE)


def parse_routes(output: str) -> dict:
    """Extract {prefix: protocol} from 'show ip route' output."""
    routes = {}
    for match in ROUTE_RE.finditer(output):
        protocol = match.group(1).strip()
        prefix = match.group(2).strip()
        routes[prefix] = protocol
    return routes


def fetch_routes(host: str, username: str, password: str, device_type: str) -> dict:
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
    }
    log.info("Connecting to %s (%s)", host, device_type)
    try:
        with ConnectHandler(**device) as conn:
            output = conn.send_command("show ip route", read_timeout=30)
        log.info("Retrieved routing table (%d lines)", output.count("\n"))
        return parse_routes(output)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", host)
        sys.exit(1)


def save_snapshot(host: str, label: str, routes: dict) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = Path(f"{host}_{label}_{ts}.json")
    payload = {"host": host, "label": label, "timestamp": ts, "routes": routes}
    filename.write_text(json.dumps(payload, indent=2))
    log.info("Snapshot saved: %s (%d routes)", filename, len(routes))
    return filename


def load_snapshot(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        log.error("Snapshot file not found: %s", path)
        sys.exit(1)
    return json.loads(p.read_text())


def diff_snapshots(before: dict, after: dict) -> int:
    """Print a human-readable diff. Returns number of changes found."""
    b_routes = before["routes"]
    a_routes = after["routes"]

    added = {k: v for k, v in a_routes.items() if k not in b_routes}
    removed = {k: v for k, v in b_routes.items() if k not in a_routes}
    changed = {
        k: (b_routes[k], a_routes[k])
        for k in b_routes
        if k in a_routes and b_routes[k] != a_routes[k]
    }

    b_label = before.get("label", "before")
    a_label = after.get("label", "after")
    print(f"\nRoute diff: {b_label} -> {a_label}")
    print(
        f"  Before: {before.get('timestamp', '?')} ({len(b_routes)} routes)  |  "
        f"After: {after.get('timestamp', '?')} ({len(a_routes)} routes)\n"
    )

    if not added and not removed and not changed:
        print("  No routing changes detected.")
        return 0

    if added:
        print(f"  ADDED ({len(added)}):")
        for prefix, proto in sorted(added.items()):
            print(f"    + {prefix:<25} [{proto}]")

    if removed:
        print(f"\n  REMOVED ({len(removed)}):")
        for prefix, proto in sorted(removed.items()):
            print(f"    - {prefix:<25} [{proto}]")

    if changed:
        print(f"\n  PROTOCOL CHANGE ({len(changed)}):")
        for prefix, (old, new) in sorted(changed.items()):
            print(f"    ~ {prefix:<25} {old} -> {new}")

    return len(added) + len(removed) + len(changed)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Capture and diff routing table snapshots around network changes."
    )
    p.add_argument("--host", help="Device IP or hostname")
    p.add_argument("--username", help="SSH username")
    p.add_argument("--password", help="SSH password (prompted if omitted)")
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument(
        "--snapshot",
        metavar="LABEL",
        help="Capture a snapshot with this label (e.g. 'pre' or 'post')",
    )
    p.add_argument(
        "--compare",
        metavar="FILE",
        help="Snapshot JSON to diff the new capture against",
    )
    p.add_argument(
        "--diff",
        nargs=2,
        metavar=("BEFORE", "AFTER"),
        help="Diff two existing snapshot files without connecting to a device",
    )
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.diff:
        before = load_snapshot(args.diff[0])
        after = load_snapshot(args.diff[1])
        changes = diff_snapshots(before, after)
        sys.exit(0 if changes == 0 else 1)

    if not args.host or not args.snapshot:
        parser.error("--host and --snapshot are required when not using --diff")

    password = args.password or getpass(f"Password for {args.username}@{args.host}: ")
    routes = fetch_routes(args.host, args.username, password, args.device_type)
    save_snapshot(args.host, args.snapshot, routes)

    if args.compare:
        before = load_snapshot(args.compare)
        after_payload = {
            "host": args.host,
            "label": args.snapshot,
            "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "routes": routes,
        }
        changes = diff_snapshots(before, after_payload)
        sys.exit(0 if changes == 0 else 1)