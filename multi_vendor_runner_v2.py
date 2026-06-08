The request is fully specified with exact output format ("Output ONLY the script content"). Writing the VLAN consistency auditor now — not covered by any existing scripts in the repo.

```python
"""
vlan_audit.py - Cross-device VLAN consistency auditor

Purpose:
    Connects to one or more switches and audits VLAN configuration for
    consistency. Identifies VLANs present on some devices but absent on
    others, and flags VLAN name mismatches across the fleet.

Usage:
    # Single device — dump VLAN table
    python vlan_audit.py -H 192.168.1.1 -u admin -p secret

    # Multi-device consistency check from a hosts file
    python vlan_audit.py -f devices.txt -u admin -p secret

    # Scope check to specific VLANs / ranges
    python vlan_audit.py -f devices.txt -u admin -p secret --vlans 10,20,100-199

    # Emit JSON for downstream tooling
    python vlan_audit.py -f devices.txt -u admin -p secret --json

    devices.txt format (one entry per line):
        <host>  <device_type>
    Example:
        192.168.1.1  cisco_ios
        192.168.1.2  arista_eos
        192.168.1.3  cisco_nxos

Prerequisites:
    pip install netmiko
    SSH access with read privileges (show vlan) on each device.
"""

import argparse
import json
import logging
import re
import sys
from collections import defaultdict

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
    stream=sys.stderr,
)
log = logging.getLogger(__name__)

SHOW_VLAN_CMD = {
    "cisco_ios": "show vlan brief",
    "cisco_xe": "show vlan brief",
    "cisco_nxos": "show vlan brief",
    "arista_eos": "show vlan",
}

# Matches Cisco/Arista: 10   Management  active    Gi0/1
_VLAN_ROW = re.compile(
    r"^(\d+)\s+(\S+)\s+"
    r"(active|inactive|act/lshut|act/unsup|suspended|sus/lshut|unsup)",
    re.MULTILINE,
)


def parse_vlans(output):
    """Return {vlan_id (int): name (str)} from show vlan output."""
    return {int(m.group(1)): m.group(2) for m in _VLAN_ROW.finditer(output)}


def expand_vlan_spec(spec):
    """Parse '10,20,100-199' into a set of ints."""
    ids = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ids.update(range(int(lo), int(hi) + 1))
        else:
            ids.add(int(part))
    return ids


def fetch_vlans(host, device_type, username, password, port):
    """SSH to device and return its VLAN table, or None on failure."""
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "timeout": 30,
    }
    try:
        log.info("Connecting to %s (%s)", host, device_type)
        with ConnectHandler(**params) as conn:
            cmd = SHOW_VLAN_CMD.get(device_type, "show vlan brief")
            output = conn.send_command(cmd)
        return parse_vlans(output)
    except AuthenticationException:
        log.error("%s: authentication failed", host)
    except NetmikoTimeoutException:
        log.error("%s: connection timed out", host)
    except Exception as exc:
        log.error("%s: %s", host, exc)
    return None


def consistency_report(device_vlans):
    """
    Compare VLAN tables across devices.
    Returns {'missing': {vid: [hosts]}, 'name_conflicts': {vid: {host: name}}}.
    """
    all_vids = set()
    for vlans in device_vlans.values():
        all_vids.update(vlans)

    missing = defaultdict(list)
    conflicts = {}

    for vid in sorted(all_vids):
        names = {}
        for host, vlans in device_vlans.items():
            if vid not in vlans:
                missing[vid].append(host)
            else:
                names[host] = vlans[vid]
        if len(set(names.values())) > 1:
            conflicts[vid] = names

    return {"missing": dict(missing), "name_conflicts": conflicts}


def load_hosts_file(path):
    entries = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            entries.append((parts[0], parts[1] if len(parts) > 1 else "cisco_ios"))
    return entries


def main():
    parser = argparse.ArgumentParser(
        description="Audit VLAN consistency across network switches."
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("-H", "--host", help="Single device IP/hostname")
    src.add_argument("-f", "--hosts-file", help="File listing host + device_type pairs")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument(
        "-t", "--device-type", default="cisco_ios",
        help="Netmiko device type (single-host mode only, default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument(
        "--vlans",
        help="Comma/range filter, e.g. '10,20,100-199'. Default: all VLANs.",
    )
    parser.add_argument(
        "--json", dest="json_out", action="store_true",
        help="Emit results as JSON",
    )
    args = parser.parse_args()

    hosts = [(args.host, args.device_type)] if args.host else load_hosts_file(args.hosts_file)

    device_vlans = {}
    for host, dtype in hosts:
        vlans = fetch_vlans(host, dtype, args.username, args.password, args.port)
        if vlans is not None:
            device_vlans[host] = vlans

    if not device_vlans:
        log.error("No devices responded successfully.")
        sys.exit(1)

    if args.vlans:
        wanted = expand_vlan_spec(args.vlans)
        device_vlans = {
            h: {k: v for k, v in vlans.items() if k in wanted}
            for h, vlans in device_vlans.items()
        }

    if args.json_out:
        out = {"inventory": {h: dict(sorted(v.items())) for h, v in device_vlans.items()}}
        if len(device_vlans) > 1:
            out["audit"] = consistency_report(device_vlans)
        print(json.dumps(out, indent=2))
        return

    for host, vlans in device_vlans.items():
        print(f"\n{'=' * 52}")
        print(f"  {host}  —  {len(vlans)} VLANs")
        print(f"{'=' * 52}")
        print(f"  {'ID':<8} {'Name'}")
        print(f"  {'-'*7} {'-'*30}")
        for vid, name in sorted(vlans.items()):
            print(f"  {vid:<8} {name}")

    if len(device_vlans) > 1:
        report = consistency_report(device_vlans)
        print(f"\n{'=' * 52}")
        print("  CONSISTENCY REPORT")
        print(f"{'=' * 52}")
        if report["missing"]:
            print("\n  Missing VLANs:")
            for vid, absent in sorted(report["missing"].items()):
                print(f"    VLAN {vid}: absent on {', '.join(absent)}")
        else:
            print("\n  No missing VLANs.")
        if report["name_conflicts"]:
            print("\n  Name Conflicts:")
            for vid, host_names in sorted(report["name_conflicts"].items()):
                detail = ", ".join(f"{h}={n}" for h, n in host_names.items())
                print(f"    VLAN {vid}: {detail}")
        else:
            print("  No name conflicts.")


if __name__ == "__main__":
    main()
```