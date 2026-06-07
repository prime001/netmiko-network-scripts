```python
"""
mac_port_mapper.py - Map MAC addresses to switch ports with optional ARP IP correlation.

Purpose:
    Connects to a Cisco IOS/IOS-XE switch via SSH, retrieves the MAC address table
    and optionally the ARP table, then produces a report mapping MACs to switch ports
    and (when --arp is set) their associated IP addresses. Useful for device location
    tracking, rogue device detection, and network audits.

Usage:
    python mac_port_mapper.py -d 192.168.1.1 -u admin -p secret
    python mac_port_mapper.py -d 192.168.1.1 -u admin -p secret --arp
    python mac_port_mapper.py -d 192.168.1.1 -u admin -p secret --vlan 100
    python mac_port_mapper.py -d 192.168.1.1 -u admin -p secret --mac 00:1a:2b:3c:4d:5e
    python mac_port_mapper.py -d 192.168.1.1 -u admin -p secret --output results.csv

Prerequisites:
    - netmiko >= 4.0: pip install netmiko
    - SSH access to a Cisco IOS/IOS-XE switch
    - Account with 'show' command privileges
"""

import argparse
import csv
import logging
import re
import sys

from netmiko import ConnectHandler
from netmiko.exceptions import NetMikoAuthenticationException, NetMikoTimeoutException


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def parse_mac_table(output):
    """Parse 'show mac address-table' into list of dicts."""
    entries = []
    pattern = re.compile(
        r"^\s*(\d+)\s+([\da-f]{4}\.[\da-f]{4}\.[\da-f]{4})\s+(\w+)\s+([\w/.:()-]+)",
        re.IGNORECASE | re.MULTILINE,
    )
    for match in pattern.finditer(output):
        entries.append({
            "vlan": match.group(1),
            "mac": match.group(2).lower(),
            "type": match.group(3),
            "port": match.group(4),
            "ip": "",
        })
    return entries


def parse_arp_table(output):
    """Parse 'show ip arp' and return a mac -> ip mapping dict."""
    arp_map = {}
    pattern = re.compile(
        r"^\s*Internet\s+([\d.]+)\s+\S+\s+([\da-f]{4}\.[\da-f]{4}\.[\da-f]{4})",
        re.IGNORECASE | re.MULTILINE,
    )
    for match in pattern.finditer(output):
        arp_map[match.group(2).lower()] = match.group(1)
    return arp_map


def normalize_mac(mac_str):
    """Accept any common MAC format; return Cisco dotted-quartet notation."""
    digits = re.sub(r"[^0-9a-fA-F]", "", mac_str).lower()
    if len(digits) != 12:
        raise ValueError(f"Invalid MAC address: {mac_str!r}")
    return f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}"


def print_table(entries):
    if not entries:
        print("No entries matched the specified filters.")
        return
    header = f"{'VLAN':<6} {'MAC':<16} {'TYPE':<10} {'PORT':<26} {'IP':<17}"
    print(header)
    print("-" * len(header))
    for e in entries:
        print(f"{e['vlan']:<6} {e['mac']:<16} {e['type']:<10} {e['port']:<26} {e['ip']:<17}")
    print(f"\nTotal: {len(entries)} entries")


def write_csv(entries, filepath):
    fieldnames = ["vlan", "mac", "type", "port", "ip"]
    with open(filepath, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(entries)
    logger.info("Results written to %s", filepath)


def build_parser():
    p = argparse.ArgumentParser(
        description="Map switch MAC address table to ports with optional ARP IP correlation."
    )
    p.add_argument("-d", "--device", required=True, help="Switch IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)"
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--mac", help="Filter by MAC address (any standard format)")
    p.add_argument("--vlan", help="Filter by VLAN ID")
    p.add_argument(
        "--interface",
        help="Filter by port name substring (e.g. 'Gi1/0' or 'Fa0')"
    )
    p.add_argument(
        "--arp", action="store_true",
        help="Fetch ARP table and correlate IPs to MAC entries"
    )
    p.add_argument("--output", help="Write results to a CSV file instead of stdout")
    return p


def main():
    args = build_parser().parse_args()

    mac_filter = None
    if args.mac:
        try:
            mac_filter = normalize_mac(args.mac)
        except ValueError as exc:
            logger.error(exc)
            sys.exit(1)

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }

    try:
        logger.info("Connecting to %s", args.device)
        with ConnectHandler(**device_params) as conn:
            logger.info("Retrieving MAC address table")
            mac_output = conn.send_command("show mac address-table")

            arp_map = {}
            if args.arp:
                logger.info("Retrieving ARP table")
                arp_map = parse_arp_table(conn.send_command("show ip arp"))

    except NetMikoAuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except NetMikoTimeoutException:
        logger.error("Connection to %s timed out", args.device)
        sys.exit(1)
    except Exception as exc:
        logger.error("Unexpected error: %s", exc)
        sys.exit(1)

    entries = parse_mac_table(mac_output)
    logger.info("Parsed %d MAC table entries", len(entries))

    for entry in entries:
        entry["ip"] = arp_map.get(entry["mac"], "")

    if mac_filter:
        entries = [e for e in entries if e["mac"] == mac_filter]
    if args.vlan:
        entries = [e for e in entries if e["vlan"] == args.vlan]
    if args.interface:
        substr = args.interface.lower()
        entries = [e for e in entries if substr in e["port"].lower()]

    if args.output:
        write_csv(entries, args.output)
    else:
        print_table(entries)


if __name__ == "__main__":
    main()
```