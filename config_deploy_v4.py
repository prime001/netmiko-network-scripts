The write was blocked pending your approval. Here is the complete script content:

```python
"""
vlan_provisioner.py - VLAN lifecycle management via netmiko

Purpose:
    Create, delete, or verify VLANs on Cisco IOS/IOS-XE switches and
    optionally assign them to access or trunk interfaces in a single pass.

Usage:
    # Create VLAN 100 named SERVERS
    python vlan_provisioner.py -d 192.168.1.1 -u admin -p secret \
        --action create --vlan 100 --name SERVERS

    # Assign VLAN 100 as access port on Gi0/1
    python vlan_provisioner.py -d 192.168.1.1 -u admin -p secret \
        --action create --vlan 100 --name SERVERS \
        --access-port GigabitEthernet0/1

    # Add VLAN 100 to a trunk
    python vlan_provisioner.py -d 192.168.1.1 -u admin -p secret \
        --action create --vlan 100 --trunk-port GigabitEthernet0/2

    # Verify VLAN exists and is active
    python vlan_provisioner.py -d 192.168.1.1 -u admin -p secret \
        --action verify --vlan 100

    # Delete VLAN
    python vlan_provisioner.py -d 192.168.1.1 -u admin -p secret \
        --action delete --vlan 100

Prerequisites:
    pip install netmiko
    Cisco IOS/IOS-XE device with SSH enabled and privilege 15 access.
"""

import argparse
import logging
import sys

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def build_device(args):
    return {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "secret": args.enable_secret or args.password,
        "port": args.port,
        "timeout": 30,
    }


def vlan_exists(conn, vlan_id):
    output = conn.send_command(f"show vlan id {vlan_id}", use_textfsm=False)
    return f"VLAN {vlan_id}" in output and "not found" not in output.lower()


def create_vlan(conn, vlan_id, vlan_name):
    cmds = [f"vlan {vlan_id}"]
    if vlan_name:
        cmds.append(f"name {vlan_name}")
    cmds.append("exit")
    output = conn.send_config_set(cmds)
    log.debug("create_vlan output:\n%s", output)

    if not vlan_exists(conn, vlan_id):
        raise RuntimeError(f"VLAN {vlan_id} not present after creation — check device logs")

    log.info("VLAN %s (%s) created successfully", vlan_id, vlan_name or "no-name")


def delete_vlan(conn, vlan_id):
    if not vlan_exists(conn, vlan_id):
        log.warning("VLAN %s does not exist — nothing to delete", vlan_id)
        return

    output = conn.send_config_set([f"no vlan {vlan_id}"])
    log.debug("delete_vlan output:\n%s", output)

    if vlan_exists(conn, vlan_id):
        raise RuntimeError(f"VLAN {vlan_id} still present after deletion")

    log.info("VLAN %s deleted successfully", vlan_id)


def assign_access_port(conn, vlan_id, interface):
    cmds = [
        f"interface {interface}",
        "switchport mode access",
        f"switchport access vlan {vlan_id}",
        "no shutdown",
        "exit",
    ]
    output = conn.send_config_set(cmds)
    log.debug("assign_access_port output:\n%s", output)
    log.info("Interface %s set to access VLAN %s", interface, vlan_id)


def assign_trunk_port(conn, vlan_id, interface):
    cmds = [
        f"interface {interface}",
        "switchport mode trunk",
        f"switchport trunk allowed vlan add {vlan_id}",
        "exit",
    ]
    output = conn.send_config_set(cmds)
    log.debug("assign_trunk_port output:\n%s", output)
    log.info("VLAN %s added to trunk on %s", vlan_id, interface)


def verify_vlan(conn, vlan_id):
    if not vlan_exists(conn, vlan_id):
        log.error("VLAN %s is NOT present on this device", vlan_id)
        return False

    output = conn.send_command(f"show vlan id {vlan_id}", use_textfsm=False)
    is_active = "active" in output.lower()
    status = "ACTIVE" if is_active else "INACTIVE/SUSPENDED"
    log.info("VLAN %s verification: %s", vlan_id, status)
    print(output)
    return is_active


def parse_args():
    parser = argparse.ArgumentParser(
        description="VLAN provisioning and verification for Cisco IOS/IOS-XE"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("-e", "--enable-secret", default=None, help="Enable secret (defaults to password)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--device-type", default="cisco_ios",
        choices=["cisco_ios", "cisco_xe", "cisco_nxos"],
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument(
        "--action", required=True,
        choices=["create", "delete", "verify"],
        help="Operation to perform",
    )
    parser.add_argument("--vlan", required=True, type=int, help="VLAN ID (1-4094)")
    parser.add_argument("--name", default=None, help="VLAN name (for create action)")
    parser.add_argument("--access-port", default=None, metavar="INTERFACE",
                        help="Assign VLAN as access port on this interface")
    parser.add_argument("--trunk-port", default=None, metavar="INTERFACE",
                        help="Add VLAN to allowed list on this trunk interface")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not 1 <= args.vlan <= 4094:
        log.error("VLAN ID must be between 1 and 4094")
        sys.exit(1)

    device = build_device(args)
    log.info("Connecting to %s (%s)", args.device, args.device_type)

    try:
        with ConnectHandler(**device) as conn:
            conn.enable()

            if args.action == "create":
                create_vlan(conn, args.vlan, args.name)
                if args.access_port:
                    assign_access_port(conn, args.vlan, args.access_port)
                if args.trunk_port:
                    assign_trunk_port(conn, args.vlan, args.trunk_port)
                conn.save_config()
                log.info("Configuration saved")

            elif args.action == "delete":
                delete_vlan(conn, args.vlan)
                conn.save_config()
                log.info("Configuration saved")

            elif args.action == "verify":
                ok = verify_vlan(conn, args.vlan)
                sys.exit(0 if ok else 1)

    except AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.device)
        sys.exit(1)
    except RuntimeError as exc:
        log.error("Operation failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

This is `vlan_provisioner.py` — a VLAN lifecycle manager covering create/delete/verify plus optional access-port and trunk-port assignment in one shot. It's distinct from everything already in the repo (no overlap with config_deploy, health_check, port_bounce, etc.) and covers a workflow network engineers run constantly.