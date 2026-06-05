```python
"""
interface_state_snapshot.py - Pre/post change interface state capture and diff tool.

Purpose:
    Captures interface operational state (admin/protocol status, error counters) from a
    network device and optionally compares against a previously saved snapshot to surface
    regressions introduced during a maintenance window.

Usage:
    # Capture pre-change baseline:
    python interface_state_snapshot.py --host 192.168.1.1 --user admin --password secret \
        --save pre_change.json

    # Capture post-change state and compare:
    python interface_state_snapshot.py --host 192.168.1.1 --user admin --password secret \
        --save post_change.json --compare pre_change.json

    Exit code 0 = clean, exit code 2 = changes detected.

Prerequisites:
    pip install netmiko
    Supported device types: cisco_ios, cisco_nxos, arista_eos
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)

SHOW_CMD = {
    "cisco_ios": "show interfaces",
    "cisco_nxos": "show interface",
    "arista_eos": "show interfaces",
}

_RE_INTF = re.compile(r"^(\S+) is (up|down|administratively down)", re.IGNORECASE)
_RE_PROTO = re.compile(r"line protocol is (\S+)", re.IGNORECASE)
_RE_IN_ERR = re.compile(r"(\d+) input errors", re.IGNORECASE)
_RE_OUT_ERR = re.compile(r"(\d+) output errors", re.IGNORECASE)
_RE_CRC = re.compile(r"(\d+) CRC", re.IGNORECASE)
_RE_RESETS = re.compile(r"(\d+) interface resets", re.IGNORECASE)


def _parse_interfaces(output):
    interfaces = {}
    current = None

    for line in output.splitlines():
        m = _RE_INTF.match(line)
        if m:
            current = m.group(1)
            raw_state = m.group(2).lower()
            admin = "admin-down" if "administratively" in raw_state else raw_state
            interfaces[current] = {
                "admin": admin,
                "protocol": "unknown",
                "input_errors": 0,
                "output_errors": 0,
                "crc": 0,
                "resets": 0,
            }
            pm = _RE_PROTO.search(line)
            if pm:
                interfaces[current]["protocol"] = pm.group(1).rstrip(",")
            continue

        if current is None:
            continue

        pm = _RE_PROTO.search(line)
        if pm and interfaces[current]["protocol"] == "unknown":
            interfaces[current]["protocol"] = pm.group(1).rstrip(",")
        for pattern, field in (
            (_RE_IN_ERR, "input_errors"),
            (_RE_OUT_ERR, "output_errors"),
            (_RE_CRC, "crc"),
            (_RE_RESETS, "resets"),
        ):
            fm = pattern.search(line)
            if fm:
                interfaces[current][field] = int(fm.group(1))

    return interfaces


def take_snapshot(host, username, password, device_type, port):
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
    }
    cmd = SHOW_CMD.get(device_type, "show interfaces")
    log.info("Connecting to %s as %s", host, username)
    try:
        with ConnectHandler(**device) as conn:
            log.info("Running: %s", cmd)
            output = conn.send_command(cmd)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", host)
        sys.exit(1)

    interfaces = _parse_interfaces(output)
    log.info("Captured %d interfaces", len(interfaces))
    return {
        "host": host,
        "device_type": device_type,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "interfaces": interfaces,
    }


def compare_snapshots(before, after):
    changes = []
    b_intfs = before["interfaces"]
    a_intfs = after["interfaces"]
    counter_fields = ("input_errors", "output_errors", "crc", "resets")

    for intf in sorted(set(b_intfs) | set(a_intfs)):
        if intf not in b_intfs:
            changes.append(f"NEW     {intf}: appeared after change")
            continue
        if intf not in a_intfs:
            changes.append(f"GONE    {intf}: missing after change")
            continue

        b, a = b_intfs[intf], a_intfs[intf]

        if b["admin"] != a["admin"] or b["protocol"] != a["protocol"]:
            changes.append(
                f"STATE   {intf}: {b['admin']}/{b['protocol']} "
                f"-> {a['admin']}/{a['protocol']}"
            )

        for field in counter_fields:
            delta = a.get(field, 0) - b.get(field, 0)
            if delta > 0:
                changes.append(f"COUNTER {intf}: {field} +{delta}")

    return changes


def main():
    parser = argparse.ArgumentParser(
        description="Capture and diff interface state snapshots around a change window"
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(SHOW_CMD.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--save", metavar="FILE", help="Write snapshot to this JSON file")
    parser.add_argument(
        "--compare", metavar="FILE", help="Diff current state against this saved snapshot"
    )
    parser.add_argument("--debug", action="store_true", help="Verbose debug output")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    snapshot = take_snapshot(args.host, args.user, args.password, args.device_type, args.port)

    if args.save:
        with open(args.save, "w") as fh:
            json.dump(snapshot, fh, indent=2)
        log.info("Snapshot written to %s", args.save)

    if args.compare:
        try:
            with open(args.compare) as fh:
                baseline = json.load(fh)
        except FileNotFoundError:
            log.error("Baseline file not found: %s", args.compare)
            sys.exit(1)
        except json.JSONDecodeError as exc:
            log.error("Invalid JSON in baseline: %s", exc)
            sys.exit(1)

        log.info("Comparing against baseline from %s", baseline.get("timestamp", "unknown"))
        changes = compare_snapshots(baseline, snapshot)

        if changes:
            print(f"\n{'='*60}")
            print(f"REGRESSIONS DETECTED  ({len(changes)} item(s))")
            print(f"{'='*60}")
            for c in changes:
                print(f"  {c}")
            print(f"{'='*60}\n")
            sys.exit(2)
        else:
            print("\nNo interface state changes or counter regressions detected.\n")
    elif not args.save:
        print(json.dumps(snapshot, indent=2))


if __name__ == "__main__":
    main()
```