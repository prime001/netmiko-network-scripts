```python
"""mac_locator.py - MAC Address Locator

Purpose:
    Queries the MAC address table on one or more network switches to locate
    which access port a given MAC address is currently connected to. Useful
    for tracking down rogue devices, troubleshooting connectivity issues, and
    auditing host-to-port mappings without manual CLI hopping across switches.

Usage:
    python mac_locator.py --host 192.168.1.1 --username admin --mac 00:1A:2B:3C:4D:5E
    python mac_locator.py --hosts-file switches.txt --username admin --mac aa:bb:cc:dd:ee:ff
    python mac_locator.py --host 10.0.0.1 --username admin --mac 001a.2b3c.4d5e \\
        --device-type cisco_nxos --debug

Prerequisites:
    pip install netmiko
    SSH access to target switches with read-only or higher privileges.
    Supported platforms: cisco_ios, cisco_xe, cisco_nxos, juniper_junos
"""

import argparse
import getpass
import logging
import re
import sys
from dataclasses import dataclass
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    level=logging.INFO,
    stream=sys.stdout,
)
log = logging.getLogger(__name__)

SHOW_COMMANDS = {
    "cisco_ios": "show mac address-table address {mac}",
    "cisco_xe": "show mac address-table address {mac}",
    "cisco_nxos": "show mac address-table address {mac}",
    "juniper_junos": "show ethernet-switching table {mac}",
}


@dataclass
class MACResult:
    host: str
    mac: str
    vlan: Optional[str]
    port: Optional[str]
    found: bool


def normalize_mac(mac: str) -> str:
    stripped = re.sub(r"[:\-\.]", "", mac).lower()
    if not re.fullmatch(r"[0-9a-f]{12}", stripped):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return stripped


def format_mac_for_vendor(mac: str, device_type: str) -> str:
    if device_type in ("cisco_ios", "cisco_xe", "cisco_nxos"):
        return f"{mac[:4]}.{mac[4:8]}.{mac[8:]}"
    if device_type == "juniper_junos":
        return ":".join(mac[i:i + 2] for i in range(0, 12, 2))
    return mac


def parse_mac_table(output: str, device_type: str) -> tuple[Optional[str], Optional[str]]:
    if device_type in ("cisco_ios", "cisco_xe", "cisco_nxos"):
        pattern = r"^\s*(\d+)\s+[\da-f]{4}\.[\da-f]{4}\.[\da-f]{4}\s+\S+\s+(\S+)"
    elif device_type == "juniper_junos":
        pattern = r"^\s*(\d+)\s+[\da-f:]{17}\s+\S+\s+(\S+)"
    else:
        return None, None

    match = re.search(pattern, output, re.MULTILINE | re.IGNORECASE)
    if match:
        return match.group(1), match.group(2)
    return None, None


def query_device(
    host: str, username: str, password: str, mac: str, device_type: str
) -> MACResult:
    formatted = format_mac_for_vendor(mac, device_type)
    command = SHOW_COMMANDS.get(device_type, "").format(mac=formatted)
    if not command:
        log.warning("%s: unsupported device type '%s', skipping", host, device_type)
        return MACResult(host=host, mac=mac, vlan=None, port=None, found=False)

    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "timeout": 15,
    }

    try:
        with ConnectHandler(**params) as conn:
            output = conn.send_command(command)
    except NetmikoAuthenticationException:
        log.error("%s: authentication failed", host)
        return MACResult(host=host, mac=mac, vlan=None, port=None, found=False)
    except NetmikoTimeoutException:
        log.error("%s: connection timed out", host)
        return MACResult(host=host, mac=mac, vlan=None, port=None, found=False)
    except Exception as exc:
        log.error("%s: unexpected error — %s", host, exc)
        return MACResult(host=host, mac=mac, vlan=None, port=None, found=False)

    vlan, port = parse_mac_table(output, device_type)
    if port:
        log.info("%s: found on VLAN %s port %s", host, vlan, port)
        return MACResult(host=host, mac=mac, vlan=vlan, port=port, found=True)

    log.info("%s: MAC %s not in table", host, formatted)
    return MACResult(host=host, mac=mac, vlan=None, port=None, found=False)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Locate a MAC address across one or more switches.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s --host 10.0.0.1 --username admin --mac 00:1a:2b:3c:4d:5e\n"
            "  %(prog)s --hosts-file switches.txt --username ro_user --mac 001a.2b3c.4d5e\n"
        ),
    )
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--host", metavar="IP", help="Single switch IP or hostname")
    target.add_argument(
        "--hosts-file", metavar="FILE", help="File listing one switch IP per line"
    )
    p.add_argument("--username", required=True, help="SSH username")
    p.add_argument("--password", help="SSH password (prompted if omitted)")
    p.add_argument(
        "--mac", required=True, help="MAC address to search (colon, dash, or dot notation)"
    )
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(SHOW_COMMANDS.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--debug", action="store_true", help="Enable debug-level logging")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        normalized = normalize_mac(args.mac)
    except ValueError as exc:
        log.error(exc)
        sys.exit(1)

    password = args.password or getpass.getpass(f"Password for {args.username}: ")

    if args.host:
        hosts = [args.host]
    else:
        try:
            with open(args.hosts_file) as fh:
                hosts = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except FileNotFoundError:
            log.error("Hosts file not found: %s", args.hosts_file)
            sys.exit(1)

    if not hosts:
        log.error("No hosts to query.")
        sys.exit(1)

    results = [
        query_device(h, args.username, password, normalized, args.device_type)
        for h in hosts
    ]

    hits = [r for r in results if r.found]
    if not hits:
        print(f"\nMAC {args.mac} not found on {len(hosts)} queried device(s).")
        sys.exit(2)

    print(f"\nMAC {args.mac} found on {len(hits)} device(s):")
    for r in hits:
        print(f"  {r.host:<20}  VLAN {r.vlan:<6}  port {r.port}")
```