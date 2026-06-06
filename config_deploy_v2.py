vlan_manager.py - Bulk VLAN provisioning and audit across Cisco switches.

Purpose:
    Deploy, remove, or audit VLANs across one or more Cisco IOS/IOS-XE switches
    in a single pass. Useful for VLAN standardization projects, new site buildouts,
    and pre/post-change audits.

Usage:
    # Add VLANs 100 and 200 to a switch
    python vlan_manager.py --host 192.168.1.1 --username admin --password secret \
        --action add --vlans 100,200 --names "DATA,VOICE"

    # Remove a VLAN
    python vlan_manager.py --host 192.168.1.1 --username admin --password secret \
        --action remove --vlans 300

    # Audit current VLANs (read-only)
    python vlan_manager.py --host 192.168.1.1 --username admin --password secret \
        --action audit

    # Bulk operation from hostfile (one host per line)
    python vlan_manager.py --hostfile switches.txt --username admin --password secret \
        --action add --vlans 100,200 --names "DATA,VOICE"

Prerequisites:
    pip install netmiko
    Cisco IOS or IOS-XE target with SSH enabled.
    Privilege 15 required for add/remove actions.
"""

import argparse
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def parse_vlan_brief(output):
    vlans = {}
    for line in output.splitlines():
        match = re.match(r"^(\d+)\s+(\S+)\s+active", line)
        if match:
            vlans[int(match.group(1))] = match.group(2)
    return vlans


def audit_vlans(conn, host):
    output = conn.send_command("show vlan brief")
    vlans = parse_vlan_brief(output)
    log.info("[%s] %d active VLANs", host, len(vlans))
    for vid, name in sorted(vlans.items()):
        print(f"  VLAN {vid:4d}  {name}")
    return vlans


def add_vlans(conn, host, vlan_ids, vlan_names):
    commands = []
    for i, vid in enumerate(vlan_ids):
        commands.append(f"vlan {vid}")
        if i < len(vlan_names) and vlan_names[i]:
            commands.append(f" name {vlan_names[i]}")

    log.info("[%s] Configuring VLANs: %s", host, vlan_ids)
    output = conn.send_config_set(commands)
    log.debug("[%s] Output:\n%s", host, output)

    current = parse_vlan_brief(conn.send_command("show vlan brief"))
    missing = [v for v in vlan_ids if v not in current]
    if missing:
        log.error("[%s] VLANs not in table after config: %s", host, missing)
        return False

    log.info("[%s] All VLANs verified present: %s", host, vlan_ids)
    return True


def remove_vlans(conn, host, vlan_ids):
    commands = [f"no vlan {vid}" for vid in vlan_ids]
    log.info("[%s] Removing VLANs: %s", host, vlan_ids)
    output = conn.send_config_set(commands)
    log.debug("[%s] Output:\n%s", host, output)

    current = parse_vlan_brief(conn.send_command("show vlan brief"))
    still_present = [v for v in vlan_ids if v in current]
    if still_present:
        log.error("[%s] VLANs still present after removal: %s", host, still_present)
        return False

    log.info("[%s] All VLANs confirmed removed: %s", host, vlan_ids)
    return True


def process_host(host, username, password, action, vlan_ids, vlan_names, device_type):
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
    }
    try:
        with ConnectHandler(**device) as conn:
            conn.enable()
            if action == "audit":
                audit_vlans(conn, host)
                return True
            elif action == "add":
                return add_vlans(conn, host, vlan_ids, vlan_names)
            elif action == "remove":
                return remove_vlans(conn, host, vlan_ids)
    except NetmikoAuthenticationException:
        log.error("[%s] Authentication failed", host)
    except NetmikoTimeoutException:
        log.error("[%s] Connection timed out", host)
    except Exception as exc:
        log.error("[%s] Unexpected error: %s", host, exc)
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Provision or audit VLANs across Cisco switches via Netmiko."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--host", help="Single device IP or hostname")
    target.add_argument("--hostfile", help="File with one host per line")

    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", help="SSH password (prompted if omitted)")
    parser.add_argument(
        "--action",
        required=True,
        choices=["add", "remove", "audit"],
        help="Operation to perform",
    )
    parser.add_argument(
        "--vlans",
        help="Comma-separated VLAN IDs (required for add/remove)",
    )
    parser.add_argument(
        "--names",
        default="",
        help="Comma-separated VLAN names aligned to --vlans (add only)",
    )
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}: ")

    vlan_ids = []
    vlan_names = []
    if args.action in ("add", "remove"):
        if not args.vlans:
            parser.error("--vlans is required for add/remove")
        try:
            vlan_ids = [int(v.strip()) for v in args.vlans.split(",")]
        except ValueError:
            parser.error("--vlans must be comma-separated integers")
        vlan_names = [n.strip() for n in args.names.split(",")] if args.names else []

    if args.host:
        hosts = [args.host]
    else:
        with open(args.hostfile) as f:
            hosts = [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]

    results = {}
    for host in hosts:
        results[host] = process_host(
            host, args.username, password, args.action,
            vlan_ids, vlan_names, args.device_type,
        )

    failed = [h for h, ok in results.items() if not ok]
    if failed:
        log.error("Failed hosts (%d): %s", len(failed), failed)
        sys.exit(1)

    log.info("Done. %d/%d hosts succeeded.", len(hosts) - len(failed), len(hosts))


if __name__ == "__main__":
    main()