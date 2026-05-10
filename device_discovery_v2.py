This is a generation request — I'll produce the script directly.

```python
"""
mac_table_lookup.py — MAC Address Table Collector and Host Locator

Purpose:
    Connects to a network switch, retrieves the MAC address table, and
    optionally cross-references the ARP table to resolve IP addresses.
    Useful for quickly determining which switch port and VLAN a host is
    connected to without logging in manually.

Usage:
    # Dump full MAC table
    python mac_table_lookup.py -H 192.168.1.1 -u admin -p secret

    # Locate a specific host by MAC (any format accepted)
    python mac_table_lookup.py -H 192.168.1.1 -u admin -p secret --mac aa:bb:cc:dd:ee:ff

    # Include IP addresses via ARP cross-reference, save to CSV
    python mac_table_lookup.py -H 192.168.1.1 -u admin -p secret --arp --output results.csv

Prerequisites:
    pip install netmiko
    Cisco IOS, IOS-XE, or NX-OS device with 'show mac address-table' support.
    Read-only credentials (privilege level 1) are sufficient.
"""

import argparse
import csv
import logging
import re
import sys
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger(__name__)

MAC_TABLE_CMD = "show mac address-table"
ARP_TABLE_CMD = "show ip arp"

_MAC_RE = re.compile(
    r"^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+\S+\s+(\S+)",
    re.IGNORECASE | re.MULTILINE,
)
_ARP_RE = re.compile(
    r"Internet\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})",
    re.IGNORECASE,
)
_SKIP_INTERFACES = {"CPU", "DROP", "STATIC", "ROUTER"}


def parse_mac_table(output: str) -> list[dict]:
    entries = []
    for m in _MAC_RE.finditer(output):
        vlan, mac, iface = m.group(1), m.group(2).lower(), m.group(3)
        if iface.upper() in _SKIP_INTERFACES:
            continue
        entries.append({"vlan": vlan, "mac": mac, "interface": iface, "ip": ""})
    return entries


def parse_arp_table(output: str) -> dict[str, str]:
    return {
        m.group(2).lower(): m.group(1)
        for m in _ARP_RE.finditer(output)
    }


def normalize_mac(mac: str) -> str:
    digits = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(digits) != 12:
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return f"{digits[0:4]}.{digits[4:8]}.{digits[8:12]}"


def collect(
    host: str,
    username: str,
    password: str,
    device_type: str,
    mac_filter: Optional[str],
    use_arp: bool,
) -> list[dict]:
    device_params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
    }
    log.info("Connecting to %s (%s)", host, device_type)
    try:
        with ConnectHandler(**device_params) as conn:
            log.info("Fetching MAC address table")
            entries = parse_mac_table(conn.send_command(MAC_TABLE_CMD))

            arp_map: dict[str, str] = {}
            if use_arp:
                log.info("Fetching ARP table for IP resolution")
                arp_map = parse_arp_table(conn.send_command(ARP_TABLE_CMD))

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", host)
        sys.exit(1)

    for entry in entries:
        entry["ip"] = arp_map.get(entry["mac"], "")

    if mac_filter:
        try:
            target = normalize_mac(mac_filter)
        except ValueError as exc:
            log.error(exc)
            sys.exit(1)
        entries = [e for e in entries if e["mac"] == target]

    return entries


def print_table(entries: list[dict]) -> None:
    if not entries:
        print("No matching entries.")
        return
    fmt = "{:<8}{:<20}{:<25}{}"
    print(fmt.format("VLAN", "MAC", "Interface", "IP"))
    print("-" * 70)
    for e in entries:
        print(fmt.format(e["vlan"], e["mac"], e["interface"], e["ip"]))


def write_csv(entries: list[dict], path: str) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["vlan", "mac", "interface", "ip"])
        writer.writeheader()
        writer.writerows(entries)
    log.info("Results written to %s", path)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Collect MAC address table entries and optionally resolve IPs via ARP"
    )
    p.add_argument("-H", "--host", required=True, help="Switch IP or hostname")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)
    p.add_argument(
        "-t", "--device-type",
        default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument(
        "--mac",
        metavar="MAC",
        help="Search for a single MAC (any separator format accepted)",
    )
    p.add_argument(
        "--arp",
        action="store_true",
        help="Cross-reference ARP table to populate the IP column",
    )
    p.add_argument(
        "--output",
        metavar="FILE",
        help="Write results to a CSV file",
    )
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    results = collect(
        host=args.host,
        username=args.username,
        password=args.password,
        device_type=args.device_type,
        mac_filter=args.mac,
        use_arp=args.arp,
    )

    print_table(results)
    log.info("%d entr%s collected", len(results), "y" if len(results) == 1 else "ies")

    if args.output:
        write_csv(results, args.output)
```