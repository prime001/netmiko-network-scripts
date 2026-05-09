The repo context is for the portfolio; I just need to output the script. Here it is:

```python
"""
mac_locator.py - MAC Address Table Lookup and Port Finder

Purpose:
    Query the MAC address table on one or more switches to find which port(s)
    a given MAC address (or list of MACs) is currently learned on. Useful for
    quickly tracing end-device connectivity during incidents or audits.

Usage:
    # Locate a single MAC on one device
    python mac_locator.py --host 10.0.0.1 --username admin --mac aa:bb:cc:dd:ee:ff

    # Locate multiple MACs (comma-separated)
    python mac_locator.py --host 10.0.0.1 --mac aa:bb:cc:dd:ee:ff,11:22:33:44:55:66

    # Query all MACs in a file against a multi-device CSV inventory
    python mac_locator.py --inventory switches.csv --mac-file macs.txt

    # Dump the full MAC table with no filter
    python mac_locator.py --host 10.0.0.1 --dump

    Inventory CSV columns: host, username, password[, device_type, port, secret]

Prerequisites:
    pip install netmiko
    Supported device types: cisco_ios, cisco_nxos, arista_eos
"""

import argparse
import csv
import getpass
import logging
import re
import sys
from dataclasses import dataclass
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


MAC_COMMANDS = {
    "cisco_ios": "show mac address-table",
    "cisco_nxos": "show mac address-table",
    "arista_eos": "show mac address-table",
}

# Matches: vlan  mac  type  [flags...]  port
# Handles Cisco dotted (xxxx.xxxx.xxxx) and colon-delimited formats.
_MAC_RE = re.compile(
    r"^\s*\*?\s*(?P<vlan>\d+)\s+"
    r"(?P<mac>"
    r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}"
    r"|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"
    r")\s+\S+"
    r"(?:\s+\S+)*?\s+"
    r"(?P<port>(?:Gi|Fa|Te|Fo|Hu|Et|Po|Vl|Eth|TwG)\S+)"
)


@dataclass
class MacEntry:
    device: str
    vlan: str
    mac: str
    port: str


@dataclass
class DeviceConfig:
    host: str
    username: str
    password: str
    device_type: str = "cisco_ios"
    ssh_port: int = 22
    secret: str = ""


def normalize_mac(mac: str) -> str:
    """Return MAC in Cisco dotted-hex form (aabb.ccdd.eeff)."""
    digits = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(digits) != 12:
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}"


def parse_mac_table(output: str, device_host: str) -> list[MacEntry]:
    entries = []
    for line in output.splitlines():
        m = _MAC_RE.search(line)
        if m:
            entries.append(MacEntry(
                device=device_host,
                vlan=m.group("vlan"),
                mac=normalize_mac(m.group("mac")),
                port=m.group("port"),
            ))
    return entries


def query_device(
    device: DeviceConfig, target_macs: Optional[set[str]] = None
) -> list[MacEntry]:
    cmd = MAC_COMMANDS.get(device.device_type, "show mac address-table")
    params = {
        "device_type": device.device_type,
        "host": device.host,
        "username": device.username,
        "password": device.password,
        "port": device.ssh_port,
    }
    if device.secret:
        params["secret"] = device.secret

    try:
        log.info("Connecting to %s (%s)", device.host, device.device_type)
        with ConnectHandler(**params) as conn:
            if device.secret:
                conn.enable()
            output = conn.send_command(cmd, read_timeout=30)
        entries = parse_mac_table(output, device.host)
        log.info("%s: %d entries parsed", device.host, len(entries))
        if target_macs is not None:
            entries = [e for e in entries if e.mac in target_macs]
        return entries
    except NetmikoAuthenticationException:
        log.error("%s: authentication failed", device.host)
    except NetmikoTimeoutException:
        log.error("%s: connection timed out", device.host)
    except Exception as exc:
        log.error("%s: %s", device.host, exc)
    return []


def load_inventory(path: str) -> list[DeviceConfig]:
    devices = []
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            devices.append(DeviceConfig(
                host=row["host"],
                username=row["username"],
                password=row["password"],
                device_type=row.get("device_type", "cisco_ios"),
                ssh_port=int(row.get("port", 22)),
                secret=row.get("secret", ""),
            ))
    return devices


def print_results(entries: list[MacEntry]) -> None:
    if not entries:
        print("No matching MAC entries found.")
        return
    col = (18, 6, 18, 24)
    header = f"{'Device':<{col[0]}} {'VLAN':<{col[1]}} {'MAC':<{col[2]}} {'Port':<{col[3]}}"
    print(header)
    print("-" * len(header))
    for e in sorted(entries, key=lambda x: (x.device, x.vlan, x.mac)):
        print(f"{e.device:<{col[0]}} {e.vlan:<{col[1]}} {e.mac:<{col[2]}} {e.port:<{col[3]}}")
    print(f"\n{len(entries)} entr{'y' if len(entries) == 1 else 'ies'} found.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Locate MAC addresses in switch MAC address tables.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python mac_locator.py --host 10.0.0.1 --mac aabb.ccdd.eeff",
    )
    p.add_argument("--host", help="Single device IP or hostname")
    p.add_argument("--username", default="admin", help="SSH username")
    p.add_argument("--password", default="", help="SSH password (prompted if omitted)")
    p.add_argument("--secret", default="", help="Enable secret (Cisco)")
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(MAC_COMMANDS.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--inventory", help="CSV inventory file for multi-device lookups")
    p.add_argument("--mac", help="MAC address(es) to locate, comma-separated")
    p.add_argument("--mac-file", help="File containing one MAC per line")
    p.add_argument("--dump", action="store_true", help="Dump full MAC table (no filter)")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


def main() -> int:
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.host and not args.inventory:
        print("ERROR: --host or --inventory is required.", file=sys.stderr)
        return 1

    target_macs: Optional[set[str]] = None
    if not args.dump:
        raw: list[str] = []
        if args.mac:
            raw.extend(m.strip() for m in args.mac.split(",") if m.strip())
        if args.mac_file:
            with open(args.mac_file) as fh:
                raw.extend(line.strip() for line in fh if line.strip())
        if not raw:
            print("ERROR: provide --mac, --mac-file, or --dump.", file=sys.stderr)
            return 1
        try:
            target_macs = {normalize_mac(m) for m in raw}
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        log.info("Looking for: %s", ", ".join(sorted(target_macs)))

    if args.inventory:
        devices = load_inventory(args.inventory)
    else:
        pw = args.password or getpass.getpass(f"Password for {args.host}: ")
        devices = [DeviceConfig(
            host=args.host,
            username=args.username,
            password=pw,
            device_type=args.device_type,
            ssh_port=args.port,
            secret=args.secret,
        )]

    all_entries: list[MacEntry] = []
    for dev in devices:
        all_entries.extend(query_device(dev, target_macs))

    print_results(all_entries)
    return 0 if all_entries else 2


if __name__ == "__main__":
    sys.exit(main())
```