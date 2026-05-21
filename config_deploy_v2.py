interface_desc_updater.py — Bulk interface description deployer

Purpose:
    Reads a CSV inventory that maps device IPs to interface/description
    pairs and pushes the descriptions to live devices via netmiko.
    Useful after a physical audit, cutsheet update, or when standardizing
    port documentation across a fleet.

Usage:
    python interface_desc_updater.py -u admin -p secret --inventory ports.csv
    python interface_desc_updater.py -u admin -p secret --inventory ports.csv \
        --device 10.0.0.1 --dry-run --device-type cisco_ios

    CSV format (no header; columns: device_ip, interface, description):
        10.0.0.1,GigabitEthernet0/1,UPLINK-CORE-SW01
        10.0.0.1,GigabitEthernet0/2,SRV-PROD-001-eth0
        10.0.0.2,Ethernet1/1,ACCESS-VLAN10-FINANCE

Prerequisites:
    pip install netmiko
"""

import argparse
import csv
import logging
import sys
from collections import defaultdict

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def load_inventory(path):
    """Return {device_ip: [(interface, description), ...]} from CSV."""
    inventory = defaultdict(list)
    with open(path, newline="") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 3:
                log.warning("Skipping malformed row: %s", row)
                continue
            ip, iface, desc = row[0].strip(), row[1].strip(), row[2].strip()
            if ip and iface:
                inventory[ip].append((iface, desc))
    return inventory


def build_commands(entries):
    """Return IOS-style config commands for a list of (interface, description) pairs."""
    cmds = []
    for iface, desc in entries:
        cmds.append(f"interface {iface}")
        cmds.append(f" description {desc}")
    return cmds


def push_descriptions(device_ip, entries, username, password, device_type,
                      enable_secret=None, dry_run=False):
    commands = build_commands(entries)

    if dry_run:
        log.info("[DRY-RUN] %s — %d command(s) would be sent:", device_ip, len(commands))
        for cmd in commands:
            log.info("    %s", cmd)
        return True

    params = {
        "device_type": device_type,
        "host": device_ip,
        "username": username,
        "password": password,
    }
    if enable_secret:
        params["secret"] = enable_secret

    try:
        with ConnectHandler(**params) as conn:
            if enable_secret:
                conn.enable()
            output = conn.send_config_set(commands)
            conn.save_config()
            log.info("%s — pushed descriptions for %d interface(s)", device_ip, len(entries))
            log.debug("%s raw output:\n%s", device_ip, output)
        return True
    except NetmikoAuthenticationException:
        log.error("%s — authentication failed", device_ip)
    except NetmikoTimeoutException:
        log.error("%s — connection timed out", device_ip)
    except Exception as exc:
        log.error("%s — %s: %s", device_ip, type(exc).__name__, exc)
    return False


def parse_args():
    p = argparse.ArgumentParser(
        description="Bulk-update interface descriptions from a CSV inventory."
    )
    p.add_argument("--inventory", required=True,
                   help="CSV file mapping device_ip,interface,description")
    p.add_argument("-d", "--device",
                   help="Limit execution to this device IP (must exist in CSV)")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("-e", "--enable-secret", default=None,
                   help="Enable/privileged secret (if required)")
    p.add_argument("--device-type", default="cisco_ios",
                   help="Netmiko device_type string (default: cisco_ios)")
    p.add_argument("--dry-run", action="store_true",
                   help="Print commands without connecting to devices")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Enable debug-level logging")
    return p.parse_args()


def main():
    args = parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)

    try:
        inventory = load_inventory(args.inventory)
    except FileNotFoundError:
        log.error("Inventory file not found: %s", args.inventory)
        sys.exit(1)
    except Exception as exc:
        log.error("Failed to read inventory: %s", exc)
        sys.exit(1)

    if not inventory:
        log.error("Inventory is empty — nothing to do")
        sys.exit(1)

    if args.device:
        if args.device not in inventory:
            log.error("Device %s not found in inventory", args.device)
            sys.exit(1)
        targets = {args.device: inventory[args.device]}
    else:
        targets = dict(inventory)

    log.info("Targeting %d device(s), dry_run=%s", len(targets), args.dry_run)

    succeeded, failed = [], []
    for ip, entries in targets.items():
        ok = push_descriptions(
            device_ip=ip,
            entries=entries,
            username=args.username,
            password=args.password,
            device_type=args.device_type,
            enable_secret=args.enable_secret,
            dry_run=args.dry_run,
        )
        (succeeded if ok else failed).append(ip)

    log.info("Complete — %d succeeded, %d failed", len(succeeded), len(failed))
    if failed:
        log.warning("Failed: %s", ", ".join(failed))
        sys.exit(1)


if __name__ == "__main__":
    main()