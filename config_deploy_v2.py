The user is asking me to write a standalone script, not modify this repo. I'll write the script now.

"""
vlan_provisioner.py — Bulk VLAN provisioning via Netmiko

Purpose:
    Deploy a set of VLANs from a CSV file to a Cisco IOS or NX-OS switch,
    then verify each VLAN was created successfully. Intended for initial
    switch build-out or adding new VLANs across a distribution layer.

Usage:
    python vlan_provisioner.py --host 192.168.1.10 --username admin \
        --password secret --vlan-file vlans.csv

    python vlan_provisioner.py --host 192.168.1.10 --username admin \
        --password secret --vlan-file vlans.csv --dry-run --verbose

CSV format (vlan_id required, vlan_name optional):
    10,Management
    20,Servers
    30,Voice

Prerequisites:
    pip install netmiko
    SSH must be enabled on the target device.
    Account needs privilege level sufficient for 'vlan' configuration commands.
    Supported platforms: Cisco IOS, IOS-XE, NX-OS.
"""

import argparse
import csv
import logging
import sys
from dataclasses import dataclass
from typing import List, Set, Tuple

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


@dataclass
class Vlan:
    vlan_id: int
    name: str


def load_vlans(path: str) -> List[Vlan]:
    vlans = []
    with open(path, newline="") as fh:
        for row in csv.reader(fh):
            if not row or row[0].strip().lower() in ("vlan_id", "#", ""):
                continue
            try:
                vlan_id = int(row[0].strip())
            except ValueError:
                log.warning("Skipping non-numeric row: %s", row)
                continue
            if not (1 <= vlan_id <= 4094):
                log.warning("Skipping out-of-range VLAN ID %d", vlan_id)
                continue
            name = (
                row[1].strip()
                if len(row) > 1 and row[1].strip()
                else f"VLAN{vlan_id:04d}"
            )
            vlans.append(Vlan(vlan_id=vlan_id, name=name))
    return vlans


def build_commands(vlans: List[Vlan]) -> List[str]:
    cmds = []
    for v in vlans:
        cmds.append(f"vlan {v.vlan_id}")
        cmds.append(f" name {v.name}")
    return cmds


def parse_vlan_brief(output: str) -> Set[int]:
    found = set()
    for line in output.splitlines():
        parts = line.split()
        if parts and parts[0].isdigit():
            found.add(int(parts[0]))
    return found


def verify_vlans(conn, vlans: List[Vlan]) -> Tuple[List[int], List[int]]:
    output = conn.send_command("show vlan brief")
    found = parse_vlan_brief(output)
    present = [v.vlan_id for v in vlans if v.vlan_id in found]
    missing = [v.vlan_id for v in vlans if v.vlan_id not in found]
    return present, missing


def provision(conn, vlans: List[Vlan]) -> bool:
    commands = build_commands(vlans)
    log.info("Pushing %d config lines for %d VLANs", len(commands), len(vlans))
    output = conn.send_config_set(commands)
    log.debug("Device output:\n%s", output)

    present, missing = verify_vlans(conn, vlans)
    log.info("Verified present (%d): %s", len(present), present)
    if missing:
        log.error("VLANs absent after provisioning (%d): %s", len(missing), missing)
        return False
    log.info("All %d VLANs confirmed on device", len(present))
    return True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Bulk VLAN provisioner — pushes VLANs from a CSV to a switch via SSH"
    )
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("--username", required=True, help="SSH username")
    p.add_argument("--password", required=True, help="SSH password")
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=["cisco_ios", "cisco_nxos"],
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument(
        "--vlan-file",
        required=True,
        metavar="PATH",
        help="CSV file: vlan_id[,vlan_name] — one VLAN per line",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without connecting to the device",
    )
    p.add_argument("--verbose", action="store_true", help="Enable DEBUG logging")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        vlans = load_vlans(args.vlan_file)
    except FileNotFoundError:
        log.error("VLAN file not found: %s", args.vlan_file)
        return 1
    except Exception as exc:
        log.error("Failed to read VLAN file: %s", exc)
        return 1

    if not vlans:
        log.error("No valid VLANs found in %s", args.vlan_file)
        return 1

    log.info("Loaded %d VLANs from %s", len(vlans), args.vlan_file)

    if args.dry_run:
        print(f"--- DRY RUN: commands for {args.host} ({args.device_type}) ---")
        for cmd in build_commands(vlans):
            print(f"  {cmd}")
        return 0

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }

    try:
        log.info("Connecting to %s (%s)", args.host, args.device_type)
        with ConnectHandler(**device) as conn:
            success = provision(conn, vlans)
    except AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except NetmikoTimeoutException:
        log.error("Connection to %s timed out", args.host)
        return 1
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        return 1

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())