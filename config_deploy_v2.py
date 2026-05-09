Writing a VLAN provisioner script — a practical config-deploy tool not covered by the existing scripts.

```python
"""
vlan_provisioner.py - Bulk VLAN provisioning via netmiko

Purpose:
    Deploy VLAN definitions from a CSV file to Cisco IOS/IOS-XE switches.
    Verifies each VLAN is active post-deployment and optionally saves running config.
    Skips VLANs that already exist so the script is safely re-runnable.

Usage:
    python vlan_provisioner.py --host 192.168.1.1 --username admin \
        --password secret --vlans vlans.csv [--device-type cisco_ios] \
        [--port 22] [--dry-run] [--save]

Prerequisites:
    pip install netmiko

CSV format (vlans.csv):
    vlan_id,name
    100,MGMT
    200,SERVERS
    300,USERS
"""

import argparse
import csv
import logging
import sys
from dataclasses import dataclass
from typing import List, Set

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class Vlan:
    vlan_id: int
    name: str


def load_vlans(csv_path: str) -> List[Vlan]:
    vlans = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            vlan_id = int(row["vlan_id"])
            if not 1 <= vlan_id <= 4094:
                raise ValueError(f"VLAN ID {vlan_id} out of range (1-4094)")
            vlans.append(Vlan(vlan_id=vlan_id, name=row["name"].strip()))
    log.info("Loaded %d VLANs from %s", len(vlans), csv_path)
    return vlans


def get_active_vlans(connection) -> Set[int]:
    output = connection.send_command("show vlan brief")
    active = set()
    for line in output.splitlines():
        parts = line.split()
        if parts and parts[0].isdigit():
            active.add(int(parts[0]))
    return active


def build_config_commands(vlans: List[Vlan]) -> List[str]:
    commands = []
    for v in vlans:
        commands.append(f"vlan {v.vlan_id}")
        commands.append(f" name {v.name}")
    return commands


def provision(connection, vlans: List[Vlan], dry_run: bool) -> dict:
    results = {"deployed": [], "skipped": [], "failed": []}

    existing = get_active_vlans(connection)
    to_deploy = [v for v in vlans if v.vlan_id not in existing]

    for v in vlans:
        if v.vlan_id in existing:
            log.info("VLAN %d (%s) already present — skipping", v.vlan_id, v.name)
            results["skipped"].append(v.vlan_id)

    if not to_deploy:
        log.info("All VLANs already present, nothing to do")
        return results

    commands = build_config_commands(to_deploy)
    log.info("Preparing to deploy %d VLANs", len(to_deploy))
    for cmd in commands:
        log.debug("  %s", cmd)

    if dry_run:
        log.info("[DRY RUN] Would send %d config commands", len(commands))
        results["deployed"] = [v.vlan_id for v in to_deploy]
        return results

    connection.send_config_set(commands)

    post = get_active_vlans(connection)
    for v in to_deploy:
        if v.vlan_id in post:
            log.info("VLAN %d (%s) — deployed OK", v.vlan_id, v.name)
            results["deployed"].append(v.vlan_id)
        else:
            log.error("VLAN %d (%s) — NOT present after deployment", v.vlan_id, v.name)
            results["failed"].append(v.vlan_id)

    return results


def save_config(connection) -> None:
    log.info("Saving configuration (write memory)...")
    connection.send_command("write memory", expect_string=r"#")
    log.info("Configuration saved")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Deploy VLANs from a CSV file to a network switch via SSH"
    )
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("--username", required=True, help="SSH username")
    p.add_argument("--password", required=True, help="SSH password")
    p.add_argument("--vlans", required=True, metavar="FILE", help="CSV file with vlan_id,name columns")
    p.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)"
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--dry-run", action="store_true",
        help="Parse and show planned changes without connecting"
    )
    p.add_argument(
        "--save", action="store_true",
        help="Write memory after successful deployment"
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()

    try:
        vlans = load_vlans(args.vlans)
    except FileNotFoundError:
        log.error("VLAN file not found: %s", args.vlans)
        sys.exit(1)
    except (KeyError, ValueError) as e:
        log.error("Invalid VLAN file: %s", e)
        sys.exit(1)

    if args.dry_run:
        log.info("[DRY RUN] Skipping device connection")
        for v in vlans:
            log.info("  Would deploy VLAN %d (%s)", v.vlan_id, v.name)
        sys.exit(0)

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }

    log.info("Connecting to %s:%d as %s", args.host, args.port, args.username)
    try:
        with ConnectHandler(**device) as conn:
            results = provision(conn, vlans, dry_run=False)
            if args.save and results["deployed"]:
                save_config(conn)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        sys.exit(1)
    except Exception as e:
        log.error("Unexpected error: %s", e)
        sys.exit(1)

    log.info(
        "Done — deployed: %d  skipped: %d  failed: %d",
        len(results["deployed"]),
        len(results["skipped"]),
        len(results["failed"]),
    )
    sys.exit(1 if results["failed"] else 0)


if __name__ == "__main__":
    main()
```