```python
"""
vlan_audit.py - VLAN configuration audit for Cisco IOS/IOS-XE switches.

Purpose:
    Connects to a network device and audits VLAN configuration, identifying:
    - VLANs defined but carrying no access ports and absent from all trunks
    - VLANs present on access ports but missing from every trunk (isolation risk)
    - Summary of trunk interfaces and their active VLAN counts

Usage:
    python vlan_audit.py -d 192.168.1.1 -u admin -p secret
    python vlan_audit.py -d 192.168.1.1 -u admin -p secret --unused-only
    python vlan_audit.py -d 192.168.1.1 -u admin -p secret --output report.txt

Prerequisites:
    pip install netmiko
    Tested against Cisco IOS 15.x and IOS-XE 16.x/17.x.
"""

import argparse
import logging
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Set

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# IOS internal VLANs that are always present and not meaningful to audit
_SKIP_VLANS = {"1002", "1003", "1004", "1005"}


@dataclass
class VlanInfo:
    vlan_id: str
    name: str
    status: str
    ports: List[str] = field(default_factory=list)


def expand_vlan_range(vlan_str: str) -> Set[str]:
    """Convert '1,10-12,20' -> {'1', '10', '11', '12', '20'}."""
    result: Set[str] = set()
    if not vlan_str or vlan_str in ("none", "all"):
        return result
    for part in vlan_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                lo, hi = part.split("-", 1)
                result.update(str(v) for v in range(int(lo), int(hi) + 1))
            except ValueError:
                pass
        elif part.isdigit():
            result.add(part)
    return result


def parse_vlan_brief(output: str) -> Dict[str, VlanInfo]:
    vlans: Dict[str, VlanInfo] = {}
    for line in output.splitlines():
        parts = line.split()
        if not parts or not parts[0].isdigit():
            continue
        vlan_id = parts[0]
        name = parts[1] if len(parts) > 1 else ""
        status = parts[2] if len(parts) > 2 else ""
        ports = [p.rstrip(",") for p in parts[3:]]
        vlans[vlan_id] = VlanInfo(vlan_id=vlan_id, name=name, status=status, ports=ports)
    return vlans


def parse_trunk_active_vlans(output: str) -> Dict[str, Set[str]]:
    """Parse 'show interfaces trunk', returning {interface: active_vlan_set}."""
    trunks: Dict[str, Set[str]] = {}
    in_active = False

    for line in output.splitlines():
        if "Vlans allowed and active" in line:
            in_active = True
            continue
        if in_active:
            if line.startswith("Port") and "Vlans" in line:
                in_active = False
                continue
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and not parts[0].startswith("Port"):
                trunks[parts[0]] = expand_vlan_range(parts[1])

    return trunks


def run_audit(conn, unused_only: bool) -> str:
    log.info("Fetching VLAN brief...")
    vlans = parse_vlan_brief(conn.send_command("show vlan brief"))

    log.info("Fetching trunk interfaces...")
    trunks = parse_trunk_active_vlans(conn.send_command("show interfaces trunk"))

    trunk_vlans: Set[str] = set().union(*trunks.values()) if trunks else set()

    lines: List[str] = []
    lines.append(f"\n{'=' * 60}")
    lines.append(f"VLAN AUDIT REPORT  —  {conn.host}")
    lines.append(f"{'=' * 60}")
    lines.append(f"VLANs defined : {len(vlans)}")
    lines.append(f"Trunk ports   : {len(trunks)}")
    lines.append("")

    if not unused_only:
        lines.append("Trunk Interfaces")
        lines.append("-" * 40)
        if trunks:
            for iface, vids in sorted(trunks.items()):
                lines.append(f"  {iface:<22} {len(vids):>4} active VLANs")
        else:
            lines.append("  No trunks found.")
        lines.append("")

    fully_unused = [
        v for vid, v in vlans.items()
        if not v.ports and vid not in trunk_vlans and vid not in _SKIP_VLANS
    ]
    lines.append(f"VLANs with no access ports and absent from all trunks: {len(fully_unused)}")
    lines.append("-" * 40)
    for v in sorted(fully_unused, key=lambda x: int(x.vlan_id)):
        lines.append(f"  VLAN {v.vlan_id:>4}  {v.name:<32}  [{v.status}]")
    if not fully_unused:
        lines.append("  None.")
    lines.append("")

    if not unused_only:
        access_only = [
            v for vid, v in vlans.items()
            if v.ports and vid not in trunk_vlans and vid not in _SKIP_VLANS
        ]
        lines.append(
            f"VLANs with access ports but absent from all trunks: {len(access_only)}"
        )
        lines.append("-" * 40)
        for v in sorted(access_only, key=lambda x: int(x.vlan_id)):
            preview = ", ".join(v.ports[:4]) + (" ..." if len(v.ports) > 4 else "")
            lines.append(f"  VLAN {v.vlan_id:>4}  {v.name:<32}  ports: {preview}")
        if not access_only:
            lines.append("  None.")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Audit VLAN configuration on a Cisco IOS/IOS-XE switch."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--unused-only", action="store_true",
        help="Report only VLANs with no ports and not on any trunk",
    )
    parser.add_argument("--output", metavar="FILE", help="Write report to FILE")
    args = parser.parse_args()

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }

    try:
        log.info(f"Connecting to {args.device}...")
        with ConnectHandler(**device_params) as conn:
            report = run_audit(conn, args.unused_only)
    except NetmikoAuthenticationException:
        log.error("Authentication failed — check credentials.")
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error(f"Connection timed out to {args.device}.")
        sys.exit(1)
    except Exception as exc:
        log.error(f"Unexpected error: {exc}")
        sys.exit(1)

    print(report)

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(report + "\n")
        log.info(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()
```