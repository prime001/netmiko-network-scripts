The output directory is `/opt/NetAutoCommitter` but the permission wasn't granted. Here is the complete script content:

```python
"""
mac_arp_tracker.py — Correlate ARP and MAC address tables to map IP → MAC → switchport.

Purpose:
    Locate where an IP address is physically connected by joining the router/L3-switch
    ARP table with the CAM (MAC address) table.  Useful for troubleshooting, port
    security audits, and IPAM reconciliation.

Usage:
    python mac_arp_tracker.py --device 10.0.0.1 --device-type cisco_ios \
        --username admin [--password secret] [--search 192.168.1.50] \
        [--output results.json]

Prerequisites:
    pip install netmiko
    Target device must respond to:
      - 'show ip arp'
      - 'show mac address-table'  (IOS/IOS-XE/NX-OS)
"""

import argparse
import json
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# Internet  10.0.0.1   3   aabb.cc00.0200  ARPA  GigabitEthernet0/1
ARP_RE = re.compile(
    r"^Internet\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+"
    r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+\S+\s+(\S+)",
    re.IGNORECASE | re.MULTILINE,
)

#    1    aabb.cc00.0200    DYNAMIC     Gi0/1
MAC_RE = re.compile(
    r"^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+\w+\s+(\S+)",
    re.IGNORECASE | re.MULTILINE,
)


def normalize_mac(mac: str) -> str:
    digits = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(digits) != 12:
        return mac.lower()
    return f"{digits[:4]}.{digits[4:8]}.{digits[8:]}"


def collect_arp(conn) -> dict:
    """Return {normalized_mac: {"ip": ..., "iface": ...}}."""
    output = conn.send_command("show ip arp")
    table = {}
    for ip, mac, iface in ARP_RE.findall(output):
        table[normalize_mac(mac)] = {"ip": ip, "iface": iface}
    log.info("ARP entries collected: %d", len(table))
    return table


def collect_mac_table(conn) -> dict:
    """Return {normalized_mac: {"vlan": ..., "port": ...}}."""
    output = conn.send_command("show mac address-table")
    table = {}
    for vlan, mac, port in MAC_RE.findall(output):
        table[normalize_mac(mac)] = {"vlan": vlan, "port": port}
    log.info("MAC table entries collected: %d", len(table))
    return table


def correlate(arp: dict, mac_table: dict) -> list:
    rows = []
    for mac, arp_info in arp.items():
        cam = mac_table.get(mac, {})
        rows.append(
            {
                "ip": arp_info["ip"],
                "mac": mac,
                "router_iface": arp_info["iface"],
                "vlan": cam.get("vlan", "-"),
                "switchport": cam.get("port", "not found"),
            }
        )
    return sorted(rows, key=lambda r: [int(x) for x in r["ip"].split(".")])


def apply_search(rows: list, term: str) -> list:
    t = term.lower()
    return [r for r in rows if t in r["ip"] or t in r["mac"]]


def print_table(rows: list) -> None:
    cols = [
        ("IP", "ip", 16),
        ("MAC", "mac", 18),
        ("VLAN", "vlan", 6),
        ("Router Iface", "router_iface", 22),
        ("Switchport", "switchport", 20),
    ]
    header = "  ".join(f"{h:<{w}}" for h, _, w in cols)
    print(header)
    print("-" * len(header))
    for r in rows:
        print("  ".join(f"{r[k]:<{w}}" for _, k, w in cols))
    print(f"\n{len(rows)} entry(ies) shown.")


def build_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Map IPs to MAC addresses and switchports via ARP + CAM correlation."
    )
    p.add_argument("--device", required=True, help="Device IP or hostname")
    p.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--username", required=True)
    p.add_argument("--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--search", metavar="IP_OR_MAC",
        help="Show only rows containing this IP or MAC substring",
    )
    p.add_argument("--output", metavar="FILE", help="Write JSON results to FILE")
    return p.parse_args()


if __name__ == "__main__":
    args = build_args()
    password = args.password or getpass(f"Password for {args.username}@{args.device}: ")

    try:
        log.info("Connecting to %s (%s)", args.device, args.device_type)
        with ConnectHandler(
            device_type=args.device_type,
            host=args.device,
            username=args.username,
            password=password,
            port=args.port,
        ) as conn:
            arp = collect_arp(conn)
            mac_table = collect_mac_table(conn)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out: %s", args.device)
        sys.exit(1)

    rows = correlate(arp, mac_table)

    if args.search:
        rows = apply_search(rows, args.search)
        log.info("Search '%s' matched %d row(s)", args.search, len(rows))

    if not rows:
        print("No matching entries found.")
        sys.exit(0)

    print_table(rows)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(rows, fh, indent=2)
        log.info("Results written to %s", args.output)
```

**What this script does:** `mac_arp_tracker.py` — 160 lines, fills a gap not covered by any existing script.

- Pulls `show ip arp` from a router/L3 switch to get IP→MAC mappings
- Pulls `show mac address-table` to get MAC→switchport mappings  
- Joins them on MAC address so you get a complete IP→MAC→VLAN→switchport table
- `--search` flag lets you pinpoint a specific IP or MAC in one shot
- `--output` dumps the correlated data as JSON for downstream use

It's a classic real-world troubleshooting workflow ("where is 10.0.1.42 plugged in?") that network engineers run manually all the time — this automates it into a single command.