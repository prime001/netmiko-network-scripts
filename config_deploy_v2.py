acl_deploy.py - Deploy named ACLs to Cisco IOS/IOS-XE devices from a YAML definition file.

Purpose:
    Reads extended ACL entries from a structured YAML file and pushes them to a
    target device via Netmiko. Optionally applies the ACL to a specified interface
    in a given direction. Supports dry-run mode to preview commands before execution
    and post-deploy verification.

Usage:
    python acl_deploy.py --host 192.168.1.1 --username admin --password secret \
        --acl-file acls.yaml --acl-name BLOCK_INBOUND

    Apply to an interface after deploy:
    python acl_deploy.py --host 192.168.1.1 --username admin --password secret \
        --acl-file acls.yaml --acl-name BLOCK_INBOUND \
        --interface GigabitEthernet0/1 --direction in --save

    Preview without connecting:
    python acl_deploy.py --host 192.168.1.1 --username admin --password secret \
        --acl-file acls.yaml --acl-name BLOCK_INBOUND --dry-run

Prerequisites:
    pip install netmiko pyyaml

ACL YAML format:
    acls:
      BLOCK_INBOUND:
        - permit tcp 10.0.0.0 0.0.0.255 any eq 443
        - permit tcp 10.0.0.0 0.0.0.255 any eq 80
        - deny   ip any any log
      ALLOW_MGMT:
        - permit tcp 192.168.10.0 0.0.0.255 any eq 22
        - deny   ip any any
"""

import argparse
import logging
import sys

import yaml
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def load_acl_file(path: str) -> dict:
    with open(path) as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or "acls" not in data:
        raise ValueError(f"YAML must have a top-level 'acls' mapping: {path}")
    return data["acls"]


def build_acl_commands(acl_name: str, entries: list) -> list:
    cmds = [f"ip access-list extended {acl_name}"]
    for entry in entries:
        cmds.append(f" {entry.strip()}")
    return cmds


def build_interface_commands(interface: str, acl_name: str, direction: str) -> list:
    return [
        f"interface {interface}",
        f" ip access-group {acl_name} {direction}",
    ]


def verify_acl(conn, acl_name: str) -> bool:
    output = conn.send_command(f"show ip access-lists {acl_name}")
    return f"Extended IP access list {acl_name}" in output


def deploy(args):
    acls = load_acl_file(args.acl_file)

    if args.acl_name not in acls:
        log.error(
            "ACL '%s' not found in %s. Available: %s",
            args.acl_name,
            args.acl_file,
            list(acls.keys()),
        )
        sys.exit(1)

    entries = acls[args.acl_name]
    if not entries:
        log.error("ACL '%s' has no entries in %s", args.acl_name, args.acl_file)
        sys.exit(1)

    commands = build_acl_commands(args.acl_name, entries)
    if args.interface:
        commands += build_interface_commands(args.interface, args.acl_name, args.direction)

    if args.dry_run:
        log.info("Dry run — commands that would be sent to %s:", args.host)
        for cmd in commands:
            print(f"  {cmd}")
        return

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "port": args.port,
        "username": args.username,
        "password": args.password,
        "secret": args.enable_secret or args.password,
        "conn_timeout": 30,
    }

    log.info("Connecting to %s as %s", args.host, args.username)
    try:
        with ConnectHandler(**device) as conn:
            if args.enable_secret:
                conn.enable()

            log.info(
                "Deploying ACL '%s' with %d entries", args.acl_name, len(entries)
            )
            output = conn.send_config_set(commands)
            log.debug("Config output:\n%s", output)

            if args.save:
                conn.save_config()
                log.info("Running config saved to startup")

            if verify_acl(conn, args.acl_name):
                log.info(
                    "Verification passed: ACL '%s' confirmed on %s",
                    args.acl_name,
                    args.host,
                )
            else:
                log.error(
                    "Verification failed: ACL '%s' not found after deploy", args.acl_name
                )
                sys.exit(1)

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        sys.exit(1)
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        sys.exit(1)

    log.info("ACL deploy complete on %s", args.host)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Deploy named extended ACLs to Cisco IOS/IOS-XE from a YAML file"
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument(
        "--enable-secret", default="", metavar="SECRET",
        help="Enable/privilege-exec secret (uses --password if omitted)",
    )
    parser.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--acl-file", required=True, metavar="FILE",
        help="Path to YAML file containing ACL definitions",
    )
    parser.add_argument(
        "--acl-name", required=True, metavar="NAME",
        help="Name of the ACL to deploy from the YAML file",
    )
    parser.add_argument(
        "--interface", default="", metavar="INTF",
        help="Interface to apply the ACL to after deploy (e.g. GigabitEthernet0/1)",
    )
    parser.add_argument(
        "--direction", choices=["in", "out"], default="in",
        help="ACL direction when binding to interface (default: in)",
    )
    parser.add_argument(
        "--save", action="store_true",
        help="Write memory after successful deploy",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print commands without connecting to the device",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug-level logging"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    deploy(args)