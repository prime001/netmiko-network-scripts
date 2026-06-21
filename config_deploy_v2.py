vlan_provision.py - VLAN Provisioning Tool

Purpose:
    Provision or remove a VLAN across multiple Cisco IOS/IOS-XE switches
    simultaneously, optionally adding it to trunk interface allowed lists.
    Verifies each change after applying and produces a per-device summary.

Usage:
    python vlan_provision.py --hosts 10.0.0.1 10.0.0.2 --vlan-id 100 \
        --vlan-name CORP_DATA --username admin --password secret

    python vlan_provision.py --hosts-file switches.txt --vlan-id 200 \
        --vlan-name VOICE --trunk-ports GigabitEthernet0/1 GigabitEthernet0/2

    python vlan_provision.py --hosts 10.0.0.1 --vlan-id 100 --remove \
        --trunk-ports GigabitEthernet0/1

Prerequisites:
    pip install netmiko
    SSH access with privilege 15 (or enable password) on each target switch.
    Cisco IOS or IOS-XE; adjust --device-type for other platforms.
"""

import argparse
import getpass
import logging
import sys
from typing import List, Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Provision or remove a VLAN across multiple Cisco switches."
    )
    host_group = parser.add_mutually_exclusive_group(required=True)
    host_group.add_argument("--hosts", nargs="+", metavar="IP", help="Target switch IPs")
    host_group.add_argument("--hosts-file", metavar="FILE", help="File with one IP per line")
    parser.add_argument("--vlan-id", type=int, required=True, help="VLAN ID (1-4094)")
    parser.add_argument("--vlan-name", help="VLAN name (required when provisioning)")
    parser.add_argument(
        "--trunk-ports",
        nargs="*",
        metavar="INTF",
        help="Trunk interfaces to add/remove the VLAN from (e.g. GigabitEthernet0/1)",
    )
    parser.add_argument("--remove", action="store_true", help="Remove the VLAN instead of adding it")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--enable-secret", help="Enable secret (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    return parser.parse_args()


def load_hosts(args: argparse.Namespace) -> List[str]:
    if args.hosts:
        return args.hosts
    with open(args.hosts_file) as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def build_vlan_commands(vlan_id: int, vlan_name: Optional[str], remove: bool) -> List[str]:
    if remove:
        return [f"no vlan {vlan_id}"]
    cmds = [f"vlan {vlan_id}"]
    if vlan_name:
        cmds.append(f" name {vlan_name}")
    return cmds


def build_trunk_commands(vlan_id: int, trunk_ports: List[str], remove: bool) -> List[str]:
    action = "remove" if remove else "add"
    cmds = []
    for port in trunk_ports:
        cmds += [
            f"interface {port}",
            f" switchport trunk allowed vlan {action} {vlan_id}",
        ]
    return cmds


def vlan_exists(conn, vlan_id: int) -> bool:
    output = conn.send_command(f"show vlan id {vlan_id}")
    return str(vlan_id) in output and "not found" not in output.lower()


def provision_device(
    host: str,
    vlan_id: int,
    vlan_name: Optional[str],
    trunk_ports: List[str],
    remove: bool,
    device_params: dict,
) -> dict:
    result = {"host": host, "status": "unknown", "message": ""}
    try:
        log.info("Connecting to %s", host)
        with ConnectHandler(**{**device_params, "host": host}) as conn:
            conn.enable()

            cmds = build_vlan_commands(vlan_id, vlan_name, remove)
            if trunk_ports:
                cmds += build_trunk_commands(vlan_id, trunk_ports, remove)

            output = conn.send_config_set(cmds)
            log.debug("Config output for %s:\n%s", host, output)

            conn.save_config()

            exists = vlan_exists(conn, vlan_id)
            if remove:
                ok = not exists
                msg = "VLAN removed and verified" if ok else "VLAN still present after removal"
            else:
                ok = exists
                msg = "VLAN provisioned and verified" if ok else "VLAN not found after provisioning"

            result["status"] = "ok" if ok else "error"
            result["message"] = msg

    except NetmikoAuthenticationException:
        result["status"] = "error"
        result["message"] = "Authentication failed"
        log.error("Auth failed on %s", host)
    except NetmikoTimeoutException:
        result["status"] = "error"
        result["message"] = "Connection timed out"
        log.error("Timeout on %s", host)
    except Exception as exc:
        result["status"] = "error"
        result["message"] = str(exc)
        log.error("Error on %s: %s", host, exc)

    return result


def main() -> int:
    args = parse_args()

    if not args.remove and not args.vlan_name:
        print("error: --vlan-name is required when provisioning a VLAN", file=sys.stderr)
        return 1

    if not 1 <= args.vlan_id <= 4094:
        print("error: VLAN ID must be between 1 and 4094", file=sys.stderr)
        return 1

    password = args.password or getpass.getpass("SSH password: ")
    enable_secret = args.enable_secret or getpass.getpass("Enable secret (Enter to skip): ") or None

    device_params = {
        "device_type": args.device_type,
        "username": args.username,
        "password": password,
        "port": args.port,
        "timeout": args.timeout,
    }
    if enable_secret:
        device_params["secret"] = enable_secret

    hosts = load_hosts(args)
    if not hosts:
        print("error: no hosts provided", file=sys.stderr)
        return 1

    action = "Removing" if args.remove else "Provisioning"
    vlan_label = f"{args.vlan_id}" + (f" ({args.vlan_name})" if args.vlan_name else "")
    log.info("%s VLAN %s on %d device(s)", action, vlan_label, len(hosts))

    results = []
    for host in hosts:
        r = provision_device(
            host=host,
            vlan_id=args.vlan_id,
            vlan_name=args.vlan_name,
            trunk_ports=args.trunk_ports or [],
            remove=args.remove,
            device_params=device_params,
        )
        results.append(r)
        icon = "OK" if r["status"] == "ok" else "FAIL"
        log.info("[%s] %s — %s", icon, host, r["message"])

    ok_count = sum(1 for r in results if r["status"] == "ok")
    fail_count = len(results) - ok_count
    print(f"\nResult: {ok_count}/{len(results)} succeeded, {fail_count} failed")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())