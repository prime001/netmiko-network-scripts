028_vlan_provisioner.py

Purpose:
    Provision or remove VLANs across one or more Cisco IOS/IOS-XE switches,
    then verify the VLANs exist in the VLAN database before reporting success.
    Optionally adds the VLANs to a specified trunk uplink interface.

Usage:
    python 028_vlan_provisioner.py -H 192.168.1.1 -u admin -p secret \
        --vlans 100,200,300 --names "Corp,Guest,IOT" [--trunk Gi0/1] [--remove]

Prerequisites:
    pip install netmiko
    Target device must support Cisco IOS "vlan database" or global-config VLAN commands.
"""

import argparse
import logging
import sys
from getpass import getpass

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def build_vlan_commands(vlan_ids: list[str], vlan_names: list[str], remove: bool) -> list[str]:
    cmds = []
    if remove:
        for vid in vlan_ids:
            cmds.append(f"no vlan {vid}")
    else:
        for i, vid in enumerate(vlan_ids):
            cmds.append(f"vlan {vid}")
            if i < len(vlan_names) and vlan_names[i]:
                cmds.append(f" name {vlan_names[i]}")
    return cmds


def build_trunk_commands(trunk_intf: str, vlan_ids: list[str], remove: bool) -> list[str]:
    vlan_str = ",".join(vlan_ids)
    action = "remove" if remove else "add"
    return [
        f"interface {trunk_intf}",
        f"switchport trunk allowed vlan {action} {vlan_str}",
    ]


def verify_vlans(conn, vlan_ids: list[str]) -> dict[str, bool]:
    output = conn.send_command("show vlan brief")
    results = {}
    for vid in vlan_ids:
        results[vid] = any(line.strip().startswith(vid + " ") for line in output.splitlines())
    return results


def provision(args: argparse.Namespace) -> int:
    vlan_ids = [v.strip() for v in args.vlans.split(",") if v.strip()]
    vlan_names = [n.strip() for n in args.names.split(",")] if args.names else []

    if not vlan_ids:
        log.error("No VLANs specified.")
        return 1

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "secret": args.enable or args.password,
        "port": args.port,
    }

    try:
        log.info("Connecting to %s ...", args.host)
        with ConnectHandler(**device) as conn:
            conn.enable()
            log.info("Connected. Sending VLAN config commands.")

            vlan_cmds = build_vlan_commands(vlan_ids, vlan_names, args.remove)
            output = conn.send_config_set(vlan_cmds)
            log.debug("VLAN config output:\n%s", output)

            if args.trunk:
                trunk_cmds = build_trunk_commands(args.trunk, vlan_ids, args.remove)
                t_out = conn.send_config_set(trunk_cmds)
                log.debug("Trunk config output:\n%s", t_out)

            conn.save_config()

            if args.remove:
                log.info("VLANs %s removed and config saved.", ", ".join(vlan_ids))
                return 0

            log.info("Verifying VLANs in database ...")
            results = verify_vlans(conn, vlan_ids)

        failed = [vid for vid, present in results.items() if not present]
        if failed:
            log.error("Verification FAILED — VLANs not in database: %s", ", ".join(failed))
            return 1

        for vid, present in results.items():
            status = "OK" if present else "MISSING"
            log.info("  VLAN %-6s %s", vid, status)

        log.info("All %d VLANs provisioned and verified on %s.", len(vlan_ids), args.host)
        return 0

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s.", args.username, args.host)
        return 2
    except NetmikoTimeoutException:
        log.error("Connection to %s timed out.", args.host)
        return 3
    except Exception as exc:
        log.exception("Unexpected error: %s", exc)
        return 4


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Provision or remove VLANs on a Cisco IOS switch and optionally trunk them."
    )
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument("-e", "--enable", default=None, help="Enable secret (defaults to password)")
    p.add_argument("--vlans", required=True, help="Comma-separated VLAN IDs, e.g. 100,200,300")
    p.add_argument("--names", default="", help="Comma-separated VLAN names (positional, optional)")
    p.add_argument("--trunk", default=None, help="Trunk interface to add/remove VLANs from, e.g. Gi0/1")
    p.add_argument("--remove", action="store_true", help="Remove VLANs instead of adding them")
    p.add_argument("--device-type", default="cisco_ios", help="Netmiko device type (default: cisco_ios)")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    if args.password is None:
        args.password = getpass(f"Password for {args.username}@{args.host}: ")
    sys.exit(provision(args))