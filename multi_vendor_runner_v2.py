```python
"""
mac_arp_correlator.py - Map IP addresses to MAC addresses to switch ports.

Purpose:
    Correlates ARP table entries (IP->MAC) with MAC address table entries
    (MAC->port) to produce a complete IP->MAC->interface mapping. Useful for
    locating endpoints, auditing access layers, and troubleshooting
    connectivity issues without manual network traversal.

Usage:
    python mac_arp_correlator.py -H 192.168.1.1 -u admin -p secret
    python mac_arp_correlator.py -H 10.0.0.1 -u admin -p secret --search 00:1a:2b:3c:4d:5e
    python mac_arp_correlator.py -H 10.0.0.1 -u admin -p secret --ip 192.168.1.50
    python mac_arp_correlator.py -H 10.0.0.1 -u admin -p secret --csv results.csv

Prerequisites:
    pip install netmiko
    SSH access to device with privilege level sufficient to read ARP and MAC tables.
    Supported device types: cisco_ios, cisco_nxos, arista_eos
"""

import argparse
import csv
import logging
import re
import sys
from dataclasses import dataclass

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class ArpEntry:
    ip: str
    mac: str
    interface: str


@dataclass
class MacEntry:
    mac: str
    vlan: str
    interface: str


@dataclass
class CorrelatedEntry:
    ip: str
    mac: str
    arp_interface: str
    switch_port: str
    vlan: str


def normalize_mac(mac: str) -> str:
    digits = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(digits) != 12:
        return mac.lower()
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).lower()


def parse_ios_arp(output: str) -> list[ArpEntry]:
    entries = []
    pattern = re.compile(
        r"Internet\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-fA-F.]+)\s+\S+\s+(\S+)"
    )
    for m in pattern.finditer(output):
        ip, mac, iface = m.groups()
        entries.append(ArpEntry(ip=ip, mac=normalize_mac(mac), interface=iface))
    return entries


def parse_ios_mac_table(output: str) -> list[MacEntry]:
    entries = []
    pattern = re.compile(r"^\s*(\d+)\s+([0-9a-fA-F.]+)\s+\S+\s+(\S+)", re.MULTILINE)
    for m in pattern.finditer(output):
        vlan, mac, iface = m.groups()
        entries.append(MacEntry(mac=normalize_mac(mac), vlan=vlan, interface=iface))
    return entries


def parse_nxos_arp(output: str) -> list[ArpEntry]:
    entries = []
    pattern = re.compile(
        r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]+)\s+\S+\s+(\S+)"
    )
    for m in pattern.finditer(output):
        ip, mac, iface = m.groups()
        entries.append(ArpEntry(ip=ip, mac=normalize_mac(mac), interface=iface))
    return entries


def parse_nxos_mac_table(output: str) -> list[MacEntry]:
    entries = []
    # VLAN  MAC   type  age  secure ntfy  Ports
    pattern = re.compile(
        r"^\s*(\d+)\s+([0-9a-fA-F.]+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)",
        re.MULTILINE,
    )
    for m in pattern.finditer(output):
        vlan, mac, iface = m.groups()
        entries.append(MacEntry(mac=normalize_mac(mac), vlan=vlan, interface=iface))
    return entries


DEVICE_PARSERS = {
    "cisco_ios": {
        "arp_cmd": "show ip arp",
        "mac_cmd": "show mac address-table",
        "parse_arp": parse_ios_arp,
        "parse_mac": parse_ios_mac_table,
    },
    "cisco_nxos": {
        "arp_cmd": "show ip arp",
        "mac_cmd": "show mac address-table",
        "parse_arp": parse_nxos_arp,
        "parse_mac": parse_nxos_mac_table,
    },
    "arista_eos": {
        "arp_cmd": "show ip arp",
        "mac_cmd": "show mac address-table",
        "parse_arp": parse_ios_arp,
        "parse_mac": parse_ios_mac_table,
    },
}


def correlate(arp_entries: list[ArpEntry], mac_entries: list[MacEntry]) -> list[CorrelatedEntry]:
    mac_to_port = {e.mac: e for e in mac_entries}
    results = []
    for arp in arp_entries:
        mac_entry = mac_to_port.get(arp.mac)
        results.append(
            CorrelatedEntry(
                ip=arp.ip,
                mac=arp.mac,
                arp_interface=arp.interface,
                switch_port=mac_entry.interface if mac_entry else "N/A",
                vlan=mac_entry.vlan if mac_entry else "",
            )
        )
    return results


def print_table(entries: list[CorrelatedEntry]) -> None:
    if not entries:
        print("No entries found.")
        return
    fmt = f"{'IP Address':<18} {'MAC Address':<19} {'ARP Interface':<24} {'Switch Port':<24} VLAN"
    print(fmt)
    print("-" * len(fmt))
    for e in sorted(entries, key=lambda x: tuple(int(o) for o in x.ip.split("."))):
        print(f"{e.ip:<18} {e.mac:<19} {e.arp_interface:<24} {e.switch_port:<24} {e.vlan}")


def write_csv(entries: list[CorrelatedEntry], path: str) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["ip", "mac", "arp_interface", "switch_port", "vlan"]
        )
        writer.writeheader()
        for e in entries:
            writer.writerow(
                {"ip": e.ip, "mac": e.mac, "arp_interface": e.arp_interface,
                 "switch_port": e.switch_port, "vlan": e.vlan}
            )
    log.info("Results written to %s", path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Correlate ARP and MAC address tables to map IP->MAC->port."
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument(
        "-t", "--device-type",
        default="cisco_ios",
        choices=list(DEVICE_PARSERS),
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--search", metavar="MAC", help="Filter output by MAC address")
    parser.add_argument("--ip", metavar="IP", help="Filter output by IP address")
    parser.add_argument("--csv", metavar="FILE", help="Export results to CSV")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    parsers = DEVICE_PARSERS[args.device_type]

    try:
        log.info("Connecting to %s (%s)", args.host, args.device_type)
        with ConnectHandler(
            device_type=args.device_type,
            host=args.host,
            username=args.username,
            password=args.password,
            port=args.port,
        ) as conn:
            log.info("Fetching ARP table")
            arp_raw = conn.send_command(parsers["arp_cmd"])
            log.info("Fetching MAC address table")
            mac_raw = conn.send_command(parsers["mac_cmd"])
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection to %s timed out", args.host)
        sys.exit(1)

    arp_entries = parsers["parse_arp"](arp_raw)
    mac_entries = parsers["parse_mac"](mac_raw)
    log.info("Parsed %d ARP entries, %d MAC entries", len(arp_entries), len(mac_entries))

    results = correlate(arp_entries, mac_entries)

    if args.search:
        needle = normalize_mac(args.search)
        results = [r for r in results if r.mac == needle]
    if args.ip:
        results = [r for r in results if r.ip == args.ip]

    print_table(results)

    if args.csv:
        write_csv(results, args.csv)


if __name__ == "__main__":
    main()
```