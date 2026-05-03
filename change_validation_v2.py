```python
"""
024_stp_change_guard.py — Spanning Tree Protocol Change Guard

Purpose:
    Captures STP topology baseline before a network change and compares
    it afterward, flagging any unintended topology shifts (root changes,
    port role flips, topology change counters incrementing).

Usage:
    # Capture baseline before change:
    python 024_stp_change_guard.py --host 10.0.0.1 --user admin --save-baseline baseline.json

    # Validate after change:
    python 024_stp_change_guard.py --host 10.0.0.1 --user admin --compare baseline.json

    # Check specific VLAN:
    python 024_stp_change_guard.py --host 10.0.0.1 --user admin --vlan 100 --compare baseline.json

Prerequisites:
    pip install netmiko
    Tested against: Cisco IOS, IOS-XE (device_type=cisco_ios)
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def parse_stp_output(raw: str) -> dict:
    """Extract root bridge, port roles, and TC counter from 'show spanning-tree' output."""
    state = {"root": {}, "ports": {}, "topology_changes": 0}

    root_match = re.search(r"Root ID\s+Priority\s+(\d+)\s+Address\s+([\w.]+)", raw)
    if root_match:
        state["root"] = {"priority": int(root_match.group(1)), "address": root_match.group(2)}

    tc_match = re.search(r"Number of topology changes\s+(\d+)", raw)
    if tc_match:
        state["topology_changes"] = int(tc_match.group(1))

    # Port block: Interface + Role + Sts columns
    port_pattern = re.compile(
        r"^(\S+)\s+(Root|Desg|Altn|Back|Mstr)\s+(FWD|BLK|LIS|LRN|DIS)\s+(\d+)\s+",
        re.MULTILINE,
    )
    for m in port_pattern.finditer(raw):
        state["ports"][m.group(1)] = {"role": m.group(2), "state": m.group(3), "cost": int(m.group(4))}

    return state


def collect_baseline(conn, vlan: str | None) -> dict:
    cmd = f"show spanning-tree vlan {vlan}" if vlan else "show spanning-tree"
    log.info("Collecting STP state: %s", cmd)
    raw = conn.send_command(cmd, read_timeout=30)
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "command": cmd,
        "parsed": parse_stp_output(raw),
        "raw": raw,
    }


def compare_states(before: dict, after: dict) -> list[str]:
    diffs = []
    b, a = before["parsed"], after["parsed"]

    if b["root"] != a["root"]:
        diffs.append(
            f"ROOT BRIDGE CHANGED: {b['root']} -> {a['root']}"
        )

    tc_delta = a["topology_changes"] - b["topology_changes"]
    if tc_delta > 0:
        diffs.append(f"TOPOLOGY CHANGES incremented by {tc_delta} during the change window")

    all_ports = set(b["ports"]) | set(a["ports"])
    for port in sorted(all_ports):
        bp = b["ports"].get(port)
        ap = a["ports"].get(port)
        if bp is None:
            diffs.append(f"PORT APPEARED:  {port} role={ap['role']} state={ap['state']}")
        elif ap is None:
            diffs.append(f"PORT VANISHED:  {port} was role={bp['role']} state={bp['state']}")
        else:
            if bp["role"] != ap["role"]:
                diffs.append(f"ROLE CHANGED:   {port}  {bp['role']} -> {ap['role']}")
            if bp["state"] != ap["state"]:
                diffs.append(f"STATE CHANGED:  {port}  {bp['state']} -> {ap['state']}")

    return diffs


def build_connection(args) -> dict:
    return {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.user,
        "password": args.password,
        "port": args.port,
        "timeout": 20,
    }


def main():
    parser = argparse.ArgumentParser(
        description="STP change guard — baseline capture and post-change comparison"
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--device-type", default="cisco_ios", help="Netmiko device type")
    parser.add_argument("--vlan", help="Limit scope to a specific VLAN ID")
    parser.add_argument("--save-baseline", metavar="FILE", help="Capture baseline and save to FILE")
    parser.add_argument("--compare", metavar="FILE", help="Compare current state against saved FILE")
    args = parser.parse_args()

    if not args.save_baseline and not args.compare:
        parser.error("Specify --save-baseline FILE or --compare FILE (or both)")

    if not args.password:
        args.password = getpass(f"Password for {args.user}@{args.host}: ")

    try:
        log.info("Connecting to %s:%d", args.host, args.port)
        conn = ConnectHandler(**build_connection(args))
    except AuthenticationException:
        log.error("Authentication failed for %s@%s", args.user, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        sys.exit(1)

    current = collect_baseline(conn, args.vlan)
    conn.disconnect()

    if args.save_baseline:
        with open(args.save_baseline, "w") as fh:
            json.dump(current, fh, indent=2)
        log.info("Baseline saved to %s", args.save_baseline)
        root = current["parsed"].get("root", {})
        ports = current["parsed"]["ports"]
        log.info(
            "Snapshot: root=%s priority=%s  ports=%d",
            root.get("address", "unknown"),
            root.get("priority", "?"),
            len(ports),
        )

    if args.compare:
        with open(args.compare) as fh:
            baseline = json.load(fh)
        log.info("Comparing against baseline from %s", baseline["timestamp"])
        diffs = compare_states(baseline, current)
        if diffs:
            print(f"\n[FAIL] {len(diffs)} STP difference(s) detected:\n")
            for d in diffs:
                print(f"  ! {d}")
            print()
            sys.exit(2)
        else:
            print("\n[PASS] STP topology unchanged — change validated.\n")


if __name__ == "__main__":
    main()
```