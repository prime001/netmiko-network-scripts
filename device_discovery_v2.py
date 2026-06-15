mac_arp_lookup.py - IP-to-Port Locator via ARP and MAC Address Table Correlation

Purpose:
    Locates network endpoints by correlating ARP table entries with MAC address
    table entries to identify which physical switch port an IP address is
    connected to. Useful for network documentation, connectivity troubleshooting,
    and tracking down rogue or unknown devices on the network.

Usage:
    python mac_arp_lookup.py --device 10.0.0.1 --username admin --target-ip 192.168.1.50
    python mac_arp_lookup.py --device 10.0.0.1 --username admin --ip-file targets.txt
    python mac_arp_lookup.py --device 10.0.0.1 --username admin --target-ip 192.168.1.50 \
        --device-type cisco_ios --verbose

Prerequisites:
    - netmiko >= 4.0.0  (pip install netmiko)
    - Device must support 'show ip arp' and 'show mac address-table'
    - Tested with: Cisco IOS, IOS-XE, NX-OS
"""

import argparse
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.WARNING,
)
logger = logging.getLogger(__name__)


def parse_arp_table(output):
    """Return {ip: mac} mapping from 'show ip arp' output."""
    entries = {}
    # Cisco IOS: Internet  10.0.0.1  1  aabb.cc00.0100  ARPA  GigabitEthernet0/0
    pattern = re.compile(
        r"Internet\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})",
        re.IGNORECASE,
    )
    for match in pattern.finditer(output):
        entries[match.group(1)] = match.group(2).lower()
    return entries


def parse_mac_table(output):
    """Return {mac: (vlan, port)} mapping from 'show mac address-table' output."""
    entries = {}
    # IOS/IOS-XE: 10    aabb.cc00.0100    DYNAMIC     Gi0/1
    # NX-OS:      10    aabb.cc00.0100    dynamic     Eth1/1
    pattern = re.compile(
        r"(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+\S+\s+(\S+)",
        re.IGNORECASE,
    )
    for match in pattern.finditer(output):
        vlan, mac, port = match.group(1), match.group(2).lower(), match.group(3)
        entries[mac] = (vlan, port)
    return entries


def lookup_ip(connection, target_ip):
    """Return location dict for target IP: ip, mac, vlan, port, found."""
    logger.info("Fetching ARP table")
    arp_table = parse_arp_table(connection.send_command("show ip arp"))

    if target_ip not in arp_table:
        return {"ip": target_ip, "mac": None, "vlan": None, "port": None, "found": False}

    mac = arp_table[target_ip]
    logger.info("Fetching MAC address table")
    mac_table = parse_mac_table(connection.send_command("show mac address-table"))

    if mac not in mac_table:
        return {"ip": target_ip, "mac": mac, "vlan": None, "port": None, "found": False}

    vlan, port = mac_table[mac]
    return {"ip": target_ip, "mac": mac, "vlan": vlan, "port": port, "found": True}


def print_result(result):
    ip = result["ip"]
    if not result["mac"]:
        print(f"  {ip:<16}  -> NOT IN ARP TABLE")
    elif not result["port"]:
        print(f"  {ip:<16}  MAC {result['mac']}  -> NOT IN MAC TABLE")
    else:
        print(
            f"  {ip:<16}  MAC {result['mac']}  "
            f"VLAN {result['vlan']:<5}  Port {result['port']}"
        )


def build_parser():
    parser = argparse.ArgumentParser(
        description="Locate switch ports for IP addresses via ARP/MAC table correlation."
    )
    parser.add_argument("--device", required=True, help="Switch or router IP/hostname")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", help="SSH password (prompted if omitted)")
    parser.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--timeout", type=int, default=30, help="Connection timeout in seconds"
    )

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--target-ip", help="Single IP address to locate")
    target_group.add_argument(
        "--ip-file", help="Path to file containing one IP address per line"
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    return parser


def main():
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}@{args.device}: ")

    if args.ip_file:
        try:
            with open(args.ip_file) as fh:
                target_ips = [line.strip() for line in fh if line.strip()]
        except OSError as exc:
            print(f"Cannot read IP file: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        target_ips = [args.target_ip]

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": password,
        "port": args.port,
        "timeout": args.timeout,
    }

    print(f"Connecting to {args.device}...")
    try:
        with ConnectHandler(**device_params) as conn:
            print(f"Connected. Locating {len(target_ips)} IP(s):\n")
            for ip in target_ips:
                print_result(lookup_ip(conn, ip))
    except NetmikoAuthenticationException:
        print(f"Authentication failed for {args.username}@{args.device}", file=sys.stderr)
        sys.exit(1)
    except NetmikoTimeoutException:
        print(f"Connection timed out to {args.device}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        logger.debug("Unexpected error", exc_info=True)
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()