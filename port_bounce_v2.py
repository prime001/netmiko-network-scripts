```python
"""
mac_to_port.py - MAC Address to Switch Port Mapper

Queries the MAC address table on a Cisco switch to identify which port(s)
a given MAC address is learned on. Useful for locating rogue devices,
troubleshooting connectivity, and documenting endpoint locations.

Usage:
    python mac_to_port.py -d 192.168.1.1 -u admin -p secret -m aa:bb:cc:dd:ee:ff
    python mac_to_port.py -d 192.168.1.1 -u admin -p secret -m aabb.ccdd.eeff 0011.2233.4455
    python mac_to_port.py -d 192.168.1.1 -u admin -p secret --all --vlan 100

Prerequisites:
    pip install netmiko
    Device must support: show mac address-table
    Tested against: Cisco IOS, IOS-XE
"""

import argparse
import logging
import re
import sys
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def normalize_mac(mac: str) -> str:
    """Normalize MAC to cisco dotted-quad format (xxxx.xxxx.xxxx)."""
    cleaned = re.sub(r"[.:\-]", "", mac.lower())
    if len(cleaned) != 12:
        raise ValueError(f"Invalid MAC address: {mac}")
    return f"{cleaned[0:4]}.{cleaned[4:8]}.{cleaned[8:12]}"


def parse_mac_table(output: str) -> list[dict]:
    """Parse 'show mac address-table' output into a list of entry dicts."""
    entries = []
    # Matches lines like: 100  aabb.ccdd.eeff  DYNAMIC  Gi1/0/1
    pattern = re.compile(
        r"^\s*(\d+)\s+"
        r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+"
        r"(\S+)\s+"
        r"(\S+)",
        re.IGNORECASE | re.MULTILINE,
    )
    for match in pattern.finditer(output):
        entries.append(
            {
                "vlan": match.group(1),
                "mac": match.group(2).lower(),
                "type": match.group(3),
                "interface": match.group(4),
            }
        )
    return entries


def lookup_macs(
    connection,
    macs: list[str],
    vlan_filter: Optional[str],
) -> dict[str, Optional[dict]]:
    """Return a mapping of normalized MAC -> entry (or None if not found)."""
    results = {}
    normalized = {}
    for raw in macs:
        try:
            norm = normalize_mac(raw)
            normalized[norm] = raw
            results[norm] = None
        except ValueError as exc:
            log.error(exc)

    if not normalized:
        return results

    log.info("Fetching MAC address table...")
    output = connection.send_command("show mac address-table")
    entries = parse_mac_table(output)

    for entry in entries:
        if entry["mac"] in results:
            if vlan_filter and entry["vlan"] != vlan_filter:
                continue
            results[entry["mac"]] = entry

    return results


def dump_all_entries(connection, vlan_filter: Optional[str]) -> list[dict]:
    """Return all MAC table entries, optionally filtered by VLAN."""
    cmd = f"show mac address-table vlan {vlan_filter}" if vlan_filter else "show mac address-table"
    log.info("Fetching full MAC address table...")
    output = connection.send_command(cmd)
    return parse_mac_table(output)


def build_device_params(args: argparse.Namespace) -> dict:
    return {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "conn_timeout": args.timeout,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Map MAC addresses to switch ports via netmiko"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument(
        "-m", "--macs", nargs="+", metavar="MAC",
        help="One or more MAC addresses to look up (any common format)"
    )
    parser.add_argument("--all", action="store_true", help="Dump entire MAC table")
    parser.add_argument("--vlan", metavar="VLAN_ID", help="Filter results to this VLAN")
    parser.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)"
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=15, help="Connection timeout seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if not args.macs and not args.all:
        parser.error("Provide --macs <MAC...> or --all")

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    params = build_device_params(args)

    try:
        log.info("Connecting to %s...", args.device)
        with ConnectHandler(**params) as conn:
            if args.all:
                entries = dump_all_entries(conn, args.vlan)
                if not entries:
                    log.warning("No entries found%s", f" in VLAN {args.vlan}" if args.vlan else "")
                    return 0
                print(f"\n{'VLAN':<6} {'MAC':<18} {'Type':<12} {'Interface'}")
                print("-" * 56)
                for e in entries:
                    print(f"{e['vlan']:<6} {e['mac']:<18} {e['type']:<12} {e['interface']}")
                print(f"\nTotal entries: {len(entries)}")
            else:
                results = lookup_macs(conn, args.macs, args.vlan)
                print(f"\n{'MAC':<18} {'VLAN':<6} {'Interface':<20} {'Type'}")
                print("-" * 60)
                found = 0
                for mac, entry in results.items():
                    if entry:
                        print(f"{mac:<18} {entry['vlan']:<6} {entry['interface']:<20} {entry['type']}")
                        found += 1
                    else:
                        print(f"{mac:<18} {'NOT FOUND'}")
                print(f"\nFound {found}/{len(results)} MAC(s)")

    except AuthenticationException:
        log.error("Authentication failed for user '%s' on %s", args.username, args.device)
        return 1
    except NetmikoTimeoutException:
        log.error("Connection to %s timed out after %ds", args.device, args.timeout)
        return 1
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
```