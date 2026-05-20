vlan_provisioner.py — Bulk VLAN provisioner for Cisco IOS / IOS-XE / NX-OS switches.

Purpose:
    Deploy VLAN definitions from a CSV file to a switch. Optionally creates
    SVIs (Layer 3 VLAN interfaces) with IP addresses. Verifies all VLANs
    are present in 'show vlan brief' after deployment and saves the config.

Usage:
    python vlan_provisioner.py -d 192.168.1.1 -u admin -p secret -f vlans.csv
    python vlan_provisioner.py -d 10.0.0.1 -u admin -f vlans.csv --svi --dry-run
    python vlan_provisioner.py -d 10.0.0.1 -u admin -t cisco_nxos -f vlans.csv

CSV format (header row required):
    vlan_id,name,svi_ip,svi_mask
    10,MGMT,10.10.10.1,255.255.255.0
    20,SERVERS,,
    30,VOICE,,

    svi_ip and svi_mask are optional; leave blank to skip SVI creation for that VLAN.

Prerequisites:
    pip install netmiko
    SSH access to target device with config-mode privileges.
"""

import argparse
import csv
import getpass
import logging
import sys
from dataclasses import dataclass
from typing import List, Optional

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class VlanDef:
    vlan_id: int
    name: str
    svi_ip: Optional[str] = None
    svi_mask: Optional[str] = None


def load_vlans(csv_path: str) -> List[VlanDef]:
    vlans: List[VlanDef] = []
    with open(csv_path, newline="") as fh:
        for row in csv.DictReader(fh):
            try:
                vlan_id = int(row["vlan_id"])
            except (KeyError, ValueError) as exc:
                log.warning("Skipping invalid row %s: %s", row, exc)
                continue
            vlans.append(VlanDef(
                vlan_id=vlan_id,
                name=row.get("name", f"VLAN{vlan_id}").strip() or f"VLAN{vlan_id}",
                svi_ip=row.get("svi_ip", "").strip() or None,
                svi_mask=row.get("svi_mask", "").strip() or None,
            ))
    return vlans


def build_commands(vlans: List[VlanDef], with_svi: bool) -> List[str]:
    cmds: List[str] = []
    for v in vlans:
        cmds += [f"vlan {v.vlan_id}", f" name {v.name}"]
        if with_svi and v.svi_ip and v.svi_mask:
            cmds += [
                f"interface vlan {v.vlan_id}",
                f" description {v.name}",
                f" ip address {v.svi_ip} {v.svi_mask}",
                " no shutdown",
            ]
    return cmds


def verify_vlans(conn, vlans: List[VlanDef]) -> List[int]:
    output = conn.send_command("show vlan brief")
    return [v.vlan_id for v in vlans if str(v.vlan_id) not in output]


def provision(args: argparse.Namespace, vlans: List[VlanDef]) -> bool:
    device = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }
    if args.enable_secret:
        device["secret"] = args.enable_secret

    try:
        log.info("Connecting to %s (%s)", args.device, args.device_type)
        with ConnectHandler(**device) as conn:
            if args.enable_secret:
                conn.enable()

            cmds = build_commands(vlans, args.svi)
            log.info(
                "Preparing %d config lines for %d VLANs", len(cmds), len(vlans)
            )

            if args.dry_run:
                log.info("Dry-run — commands that would be sent:")
                for c in cmds:
                    print(f"  {c}")
                return True

            conn.send_config_set(cmds)

            missing = verify_vlans(conn, vlans)
            if missing:
                log.error("VLANs not found in 'show vlan brief': %s", missing)
                return False

            log.info("All %d VLANs verified successfully", len(vlans))
            conn.save_config()
            log.info("Configuration saved")
            return True

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        return False
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.device)
        return False
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Provision VLANs from a CSV file onto a Cisco switch"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument(
        "-p", "--password", default=None, help="SSH password (prompted if omitted)"
    )
    parser.add_argument(
        "-e", "--enable-secret", default=None, help="Enable secret (if required)"
    )
    parser.add_argument(
        "-f", "--file", required=True, dest="csv_file",
        help="CSV file with VLAN definitions"
    )
    parser.add_argument(
        "-t", "--device-type", default="cisco_ios",
        choices=["cisco_ios", "cisco_xe", "cisco_nxos"],
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--svi", action="store_true",
        help="Create SVIs for VLANs that have svi_ip/svi_mask in the CSV"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print commands without connecting or applying changes"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.password is None:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        vlans = load_vlans(args.csv_file)
    except FileNotFoundError:
        log.error("CSV file not found: %s", args.csv_file)
        sys.exit(1)
    except Exception as exc:
        log.error("Failed to read CSV: %s", exc)
        sys.exit(1)

    if not vlans:
        log.error("No valid VLAN entries in %s", args.csv_file)
        sys.exit(1)

    log.info("Loaded %d VLANs from %s", len(vlans), args.csv_file)
    sys.exit(0 if provision(args, vlans) else 1)