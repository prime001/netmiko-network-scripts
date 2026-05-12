```python
"""
vlan_provisioner.py - Bulk VLAN provisioning with pre/post verification.

Purpose:
    Deploy VLANs (and optional SVIs) to Cisco IOS/IOS-XE switches from a
    YAML definition file, verify creation post-deploy, and report any drift.

Usage:
    python vlan_provisioner.py -d 10.0.0.1 -u admin -p secret -f vlans.yaml
    python vlan_provisioner.py -d 10.0.0.1 -u admin -f vlans.yaml --dry-run
    python vlan_provisioner.py -d 10.0.0.1 -u admin -f vlans.yaml --remove

Prerequisites:
    pip install netmiko pyyaml

    YAML file format (vlans.yaml):
        vlans:
          - id: 100
            name: CORP_DATA
          - id: 200
            name: CORP_VOICE
            svi_ip: 10.200.0.1/24   # optional — creates SVI with ip address
"""

import argparse
import getpass
import logging
import sys

import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def load_vlan_file(path: str) -> list:
    with open(path) as f:
        data = yaml.safe_load(f)
    vlans = data.get("vlans", [])
    for v in vlans:
        if "id" not in v or "name" not in v:
            raise ValueError(f"VLAN entry missing 'id' or 'name': {v}")
        if not (1 <= int(v["id"]) <= 4094):
            raise ValueError(f"VLAN ID out of range: {v['id']}")
    return vlans


def get_existing_vlans(conn) -> set:
    output = conn.send_command("show vlan brief", use_textfsm=True)
    if isinstance(output, list):
        return {int(row["vlan_id"]) for row in output}
    return set()


def prefix_to_mask(prefix: int) -> str:
    mask = (0xFFFFFFFF >> (32 - prefix)) << (32 - prefix)
    return ".".join(str((mask >> (8 * i)) & 0xFF) for i in reversed(range(4)))


def build_commands(vlans: list, remove: bool = False) -> list:
    cmds = []
    for v in vlans:
        vid = v["id"]
        if remove:
            cmds.append(f"no vlan {vid}")
            if v.get("svi_ip"):
                cmds.append(f"no interface vlan {vid}")
        else:
            cmds += [f"vlan {vid}", f" name {v['name']}", "exit"]
            if v.get("svi_ip"):
                ip, prefix = v["svi_ip"].split("/")
                mask = prefix_to_mask(int(prefix))
                cmds += [
                    f"interface vlan {vid}",
                    f" ip address {ip} {mask}",
                    " no shutdown",
                    "exit",
                ]
    return cmds


def provision(args: argparse.Namespace) -> int:
    vlans = load_vlan_file(args.file)
    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.device}: "
    )

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": password,
        "port": args.port,
    }

    cmds = build_commands(vlans, remove=args.remove)

    if args.dry_run:
        log.info("Dry-run — commands that would be sent:")
        for c in cmds:
            print(f"  {c}")
        return 0

    log.info("Connecting to %s", args.device)
    try:
        with ConnectHandler(**device_params) as conn:
            conn.enable()

            before = get_existing_vlans(conn)
            log.info("VLANs before: %s", sorted(before))

            output = conn.send_config_set(cmds)
            log.debug("Config output:\n%s", output)
            conn.save_config()

            after = get_existing_vlans(conn)
            target_ids = {int(v["id"]) for v in vlans}

            if args.remove:
                still_present = target_ids & after
                if still_present:
                    log.error("VLANs not removed: %s", sorted(still_present))
                    return 1
                log.info("Removed VLANs: %s", sorted(target_ids - after))
            else:
                missing = target_ids - after
                if missing:
                    log.error("VLANs not created: %s", sorted(missing))
                    return 1
                log.info(
                    "Deployed %d VLAN(s): %s",
                    len(target_ids & after),
                    sorted(target_ids & after),
                )

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        return 1
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.device)
        return 1
    except FileNotFoundError as exc:
        log.error("VLAN file not found: %s", exc)
        return 1

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Provision VLANs on Cisco IOS/IOS-XE switches from a YAML definition file.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument(
        "-f", "--file", required=True, help="Path to YAML VLAN definition file"
    )
    parser.add_argument(
        "-t",
        "--device-type",
        default="cisco_ios",
        help="Netmiko device type",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without connecting or applying",
    )
    parser.add_argument(
        "--remove",
        action="store_true",
        help="Remove listed VLANs instead of provisioning them",
    )
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(provision(parse_args()))
```