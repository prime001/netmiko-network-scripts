```python
"""
mac_tracker.py - MAC Address Location Tracker

Searches Cisco IOS/IOS-XE switches for one or more MAC addresses, reporting
the exact device and switchport where each address is learned. Useful for
endpoint tracking, incident response, and access-layer audits.

Usage:
    python mac_tracker.py --hosts 10.0.1.1 10.0.1.2 --mac 00:1a:2b:3c:4d:5e
    python mac_tracker.py --hosts-file switches.txt --mac-file macs.txt
    python mac_tracker.py --hosts 10.0.1.1 --mac aa:bb:cc:dd:ee:ff -u admin

Prerequisites:
    pip install netmiko
    SSH access with privilege level sufficient for 'show mac address-table'
    Supported device types: cisco_ios, cisco_xe (NX-OS output format differs)
"""

import argparse
import getpass
import logging
import re
import sys
from dataclasses import dataclass

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.WARNING)
log = logging.getLogger(__name__)


@dataclass
class MACEntry:
    host: str
    mac: str
    vlan: str
    interface: str
    entry_type: str


def normalize_mac(mac: str) -> str:
    digits = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(digits) != 12:
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).lower()


def parse_mac_table(host: str, output: str) -> list[MACEntry]:
    """Parse IOS 'show mac address-table' output (dotted-hex format)."""
    entries = []
    pattern = re.compile(
        r"^\s*(\d+)\s+"
        r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+"
        r"(\w+)\s+"
        r"(\S+)",
        re.IGNORECASE | re.MULTILINE,
    )
    for m in pattern.finditer(output):
        vlan, mac_raw, entry_type, iface = m.groups()
        digits = mac_raw.replace(".", "")
        mac = ":".join(digits[i:i + 2] for i in range(0, 12, 2)).lower()
        entries.append(MACEntry(host=host, mac=mac, vlan=vlan, interface=iface, entry_type=entry_type))
    return entries


def search_device(
    host: str,
    device_type: str,
    username: str,
    password: str,
    secret: str,
    port: int,
    use_enable: bool,
    targets: set[str],
) -> list[MACEntry]:
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
    }
    if secret:
        params["secret"] = secret
    try:
        with ConnectHandler(**params) as conn:
            if use_enable:
                conn.enable()
            output = conn.send_command("show mac address-table", read_timeout=30)
        all_entries = parse_mac_table(host, output)
        return [e for e in all_entries if e.mac in targets]
    except NetmikoAuthenticationException:
        log.error("[%s] Authentication failed", host)
    except NetmikoTimeoutException:
        log.error("[%s] Connection timed out", host)
    except Exception as exc:
        log.error("[%s] %s: %s", host, type(exc).__name__, exc)
    return []


def load_lines(path: str) -> list[str]:
    with open(path) as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Locate MAC addresses across Cisco IOS/IOS-XE switches"
    )
    host_group = parser.add_mutually_exclusive_group(required=True)
    host_group.add_argument("--hosts", nargs="+", metavar="IP", help="Switch IPs")
    host_group.add_argument("--hosts-file", metavar="FILE", help="File with one IP per line")

    mac_group = parser.add_mutually_exclusive_group(required=True)
    mac_group.add_argument("--mac", nargs="+", metavar="MAC", help="MAC address(es) to locate")
    mac_group.add_argument("--mac-file", metavar="FILE", help="File with one MAC per line")

    parser.add_argument("-u", "--username", default="admin")
    parser.add_argument("-p", "--password", help="Omit to prompt interactively")
    parser.add_argument("--enable", action="store_true", help="Enter enable mode after login")
    parser.add_argument("--secret", help="Enable secret (prompts if --enable is set)")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=["cisco_ios", "cisco_xe"],
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    hosts = args.hosts if args.hosts else load_lines(args.hosts_file)
    raw_macs = args.mac if args.mac else load_lines(args.mac_file)

    try:
        targets = {normalize_mac(m) for m in raw_macs}
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    password = args.password or getpass.getpass(f"Password for {args.username}: ")
    secret = ""
    if args.enable:
        secret = args.secret or getpass.getpass("Enable secret: ")

    all_found: list[MACEntry] = []
    for host in hosts:
        print(f"Searching {host}...", end=" ", flush=True)
        found = search_device(host, args.device_type, args.username, password,
                               secret, args.port, args.enable, targets)
        print(f"{len(found)} match(es)")
        all_found.extend(found)

    print()
    if not all_found:
        print("No matching MAC addresses found on any searched device.")
        return 0

    col_mac, col_vlan, col_iface, col_type, col_switch = 19, 6, 30, 10, 0
    header = f"{'MAC':<{col_mac}} {'VLAN':<{col_vlan}} {'INTERFACE':<{col_iface}} {'TYPE':<{col_type}} SWITCH"
    print(header)
    print("-" * (col_mac + col_vlan + col_iface + col_type + 40))
    for e in sorted(all_found, key=lambda x: (x.mac, x.host)):
        print(f"{e.mac:<{col_mac}} {e.vlan:<{col_vlan}} {e.interface:<{col_iface}} {e.entry_type:<{col_type}} {e.host}")

    missing = targets - {e.mac for e in all_found}
    if missing:
        print(f"\nNot found on any device: {', '.join(sorted(missing))}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
```