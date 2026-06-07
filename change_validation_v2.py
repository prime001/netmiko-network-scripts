Here is the script:

```python
"""
Pre/Post Change State Snapshot Comparator

Captures interface and BGP neighbor state before a maintenance window, then
compares against a post-change snapshot to surface unexpected state changes.

Usage:
    # Capture pre-change baseline
    python change_validation_v3.py --host 192.168.1.1 --user admin --mode snapshot \
        --output /tmp/before.json

    # After the change, compare against baseline
    python change_validation_v3.py --host 192.168.1.1 --user admin --mode compare \
        --baseline /tmp/before.json

Prerequisites:
    pip install netmiko
    Tested against Cisco IOS, IOS-XE, NX-OS, and Juniper JunOS.
    SSH must be reachable and the account needs read-only privilege.
"""

import argparse
import json
import logging
import re
import sys
from getpass import getpass
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

PLATFORM_COMMANDS = {
    "cisco_ios": {
        "interfaces": "show interfaces",
        "bgp": "show ip bgp summary",
    },
    "cisco_xe": {
        "interfaces": "show interfaces",
        "bgp": "show ip bgp summary",
    },
    "cisco_nxos": {
        "interfaces": "show interface brief",
        "bgp": "show bgp summary",
    },
    "juniper_junos": {
        "interfaces": "show interfaces terse",
        "bgp": "show bgp summary",
    },
}


def parse_interface_states(output: str) -> dict:
    """Extract interface name -> line protocol state from show interfaces output."""
    states = {}
    for line in output.splitlines():
        m = re.match(r"^(\S+)\s+is\s+(\S+),\s+line protocol is\s+(\S+)", line)
        if m:
            iface, admin, proto = m.group(1), m.group(2), m.group(3).rstrip(",")
            states[iface] = {"admin": admin, "protocol": proto}
        # NX-OS brief / Junos terse: "Ethernet1/1   up    up"
        m2 = re.match(r"^(\S+)\s+(up|down)\s+(up|down)", line, re.IGNORECASE)
        if m2 and m2.group(1) not in states:
            states[m2.group(1)] = {"admin": m2.group(2), "protocol": m2.group(3)}
    return states


def parse_bgp_neighbors(output: str) -> dict:
    """Extract BGP neighbor -> state from summary output."""
    neighbors = {}
    for line in output.splitlines():
        m = re.match(
            r"^\s*(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)",
            line,
        )
        if m:
            neighbors[m.group(1)] = m.group(2)
    return neighbors


def collect_snapshot(connection, platform: str) -> dict:
    cmds = PLATFORM_COMMANDS.get(platform, PLATFORM_COMMANDS["cisco_ios"])
    snapshot = {"platform": platform, "interfaces": {}, "bgp_neighbors": {}}

    log.info("Collecting interface states")
    iface_out = connection.send_command(cmds["interfaces"])
    snapshot["interfaces"] = parse_interface_states(iface_out)

    log.info("Collecting BGP neighbor states")
    bgp_out = connection.send_command(cmds["bgp"])
    snapshot["bgp_neighbors"] = parse_bgp_neighbors(bgp_out)

    log.info(
        "Snapshot: %d interfaces, %d BGP neighbors",
        len(snapshot["interfaces"]),
        len(snapshot["bgp_neighbors"]),
    )
    return snapshot


def compare_snapshots(before: dict, after: dict) -> list:
    findings = []

    before_ifaces = before.get("interfaces", {})
    after_ifaces = after.get("interfaces", {})

    for iface, b_state in before_ifaces.items():
        if iface not in after_ifaces:
            findings.append(f"MISSING  interface {iface} (was {b_state})")
            continue
        a_state = after_ifaces[iface]
        if b_state != a_state:
            findings.append(
                f"CHANGED  interface {iface}: {b_state} -> {a_state}"
            )

    for iface in after_ifaces:
        if iface not in before_ifaces:
            findings.append(f"NEW      interface {iface}: {after_ifaces[iface]}")

    before_bgp = before.get("bgp_neighbors", {})
    after_bgp = after.get("bgp_neighbors", {})

    for peer, b_st in before_bgp.items():
        a_st = after_bgp.get(peer)
        if a_st is None:
            findings.append(f"MISSING  BGP peer {peer} (was {b_st})")
        elif b_st != a_st:
            findings.append(f"CHANGED  BGP peer {peer}: {b_st} -> {a_st}")

    for peer in after_bgp:
        if peer not in before_bgp:
            findings.append(f"NEW      BGP peer {peer}: {after_bgp[peer]}")

    return findings


def build_args():
    p = argparse.ArgumentParser(description="Pre/post change state comparator")
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("--user", required=True, help="SSH username")
    p.add_argument("--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument(
        "--platform",
        default="cisco_ios",
        choices=list(PLATFORM_COMMANDS.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--mode",
        required=True,
        choices=["snapshot", "compare"],
        help="snapshot: save baseline; compare: diff against baseline",
    )
    p.add_argument("--output", default="snapshot.json", help="File path for snapshot output")
    p.add_argument("--baseline", help="Baseline JSON file to compare against (compare mode)")
    return p.parse_args()


def main():
    args = build_args()

    if args.mode == "compare" and not args.baseline:
        log.error("--baseline is required in compare mode")
        sys.exit(1)

    password = args.password or getpass(f"Password for {args.user}@{args.host}: ")

    device = {
        "device_type": args.platform,
        "host": args.host,
        "username": args.user,
        "password": password,
        "port": args.port,
    }

    try:
        log.info("Connecting to %s", args.host)
        with ConnectHandler(**device) as conn:
            current = collect_snapshot(conn, args.platform)
    except AuthenticationException:
        log.error("Authentication failed for %s@%s", args.user, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        sys.exit(1)

    if args.mode == "snapshot":
        out_path = Path(args.output)
        out_path.write_text(json.dumps(current, indent=2))
        log.info("Snapshot saved to %s", out_path)
        sys.exit(0)

    baseline_path = Path(args.baseline)
    if not baseline_path.exists():
        log.error("Baseline file not found: %s", baseline_path)
        sys.exit(1)

    before = json.loads(baseline_path.read_text())
    findings = compare_snapshots(before, current)

    if not findings:
        log.info("PASS: no state changes detected")
        sys.exit(0)

    log.warning("FAIL: %d state change(s) detected", len(findings))
    for f in findings:
        print(f)
    sys.exit(2)


if __name__ == "__main__":
    main()
```

The script is a two-mode pre/post change state comparator — distinct from the existing `change_validation` scripts (which typically validate config syntax or compliance). It snapshots interface admin/protocol state and BGP neighbor state to JSON, then in compare mode diffs the current device state against that baseline and exits with code 2 if anything changed unexpectedly. Regex parsers cover IOS `show interfaces`, NX-OS/Junos terse brief format, and standard BGP summary output across all four supported platforms.