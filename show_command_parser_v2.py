The script is standalone and doesn't need to live in this repo. Here it is:

```python
"""
mac_tracker.py - MAC Address Table Lookup and Export

Connects to one or more network switches via Netmiko and retrieves the MAC
address table, with optional filtering by MAC or VLAN. Useful for locating
which switchport a device is connected to without manual CLI hopping.

Usage:
    # Locate a specific MAC across one switch
    python mac_tracker.py -H 192.168.1.1 -u admin -p secret --mac 00:1a:2b:3c:4d:5e

    # Dump full MAC table to CSV
    python mac_tracker.py -H 192.168.1.1 -u admin -p secret --output macs.csv

    # Search across multiple switches (comma-separated)
    python mac_tracker.py -H 10.0.0.1,10.0.0.2 -u admin -p secret --mac aabb.cc11.2233

    # Filter by VLAN
    python mac_tracker.py -H 192.168.1.1 -u admin -p secret --vlan 100

Prerequisites:
    pip install netmiko
    Supported device types: cisco_ios, cisco_xe, cisco_nxos
"""

import argparse
import csv
import logging
import re
import sys

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def normalize_mac(mac: str) -> str:
    digits = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(digits) != 12:
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).lower()


def parse_mac_table(output: str, device_type: str) -> list[dict]:
    entries = []

    if "nxos" in device_type:
        # NX-OS: VLAN  MAC Address  Type  age  Secure  NTFY  Ports
        pattern = re.compile(
            r"^\*?\s*(\d+)\s+([0-9a-f.]+)\s+(\w+)\s+\S+\s+\S+\s+\S+\s+(\S+)",
            re.MULTILINE,
        )
    else:
        # IOS/IOS-XE: Vlan  Mac Address  Type  Ports
        pattern = re.compile(
            r"^\s*(\d+)\s+([0-9a-f.]+)\s+(\w+)\s+(\S+)",
            re.MULTILINE,
        )

    for match in pattern.finditer(output):
        vlan, mac_raw, entry_type, port = match.groups()
        try:
            mac_normalized = normalize_mac(mac_raw)
        except ValueError:
            continue
        entries.append({
            "vlan": vlan,
            "mac": mac_normalized,
            "type": entry_type,
            "port": port,
        })

    return entries


def query_device(
    host: str,
    username: str,
    password: str,
    device_type: str,
    port: int,
    use_keys: bool,
) -> list[dict]:
    connection_params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
    }
    if use_keys:
        connection_params["use_keys"] = True

    log.info("Connecting to %s (%s)", host, device_type)
    try:
        with ConnectHandler(**connection_params) as conn:
            output = conn.send_command("show mac address-table")
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", host)
        return []
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", host)
        return []
    except Exception as exc:
        log.error("Failed to connect to %s: %s", host, exc)
        return []

    entries = parse_mac_table(output, device_type)
    log.info("Retrieved %d MAC entries from %s", len(entries), host)
    for entry in entries:
        entry["host"] = host
    return entries


def write_csv(entries: list[dict], path: str) -> None:
    fields = ["host", "vlan", "mac", "type", "port"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(entries)
    log.info("Wrote %d entries to %s", len(entries), path)


def print_table(entries: list[dict]) -> None:
    header = f"{'HOST':<18} {'VLAN':<6} {'MAC':<18} {'TYPE':<10} {'PORT'}"
    print(header)
    print("-" * 70)
    for e in entries:
        print(
            f"{e['host']:<18} {e['vlan']:<6} {e['mac']:<18} "
            f"{e['type']:<10} {e['port']}"
        )
    print(f"\nTotal: {len(entries)} entries")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MAC address table lookup and export via Netmiko"
    )
    parser.add_argument("-H", "--hosts", required=True,
                        help="Comma-separated device IPs or hostnames")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument(
        "-t", "--device-type", default="cisco_ios",
        choices=["cisco_ios", "cisco_xe", "cisco_nxos"],
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--use-keys", action="store_true",
                        help="Use SSH key authentication instead of password")
    parser.add_argument("--mac", help="Search for a specific MAC address")
    parser.add_argument("--vlan", help="Filter results to a specific VLAN ID")
    parser.add_argument("--output", help="Write results to a CSV file")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    all_entries: list[dict] = []

    for host in hosts:
        entries = query_device(
            host=host,
            username=args.username,
            password=args.password,
            device_type=args.device_type,
            port=args.port,
            use_keys=args.use_keys,
        )
        all_entries.extend(entries)

    if not all_entries:
        log.error("No MAC entries retrieved from any device")
        sys.exit(1)

    if args.mac:
        try:
            search_mac = normalize_mac(args.mac)
        except ValueError as exc:
            log.error("%s", exc)
            sys.exit(1)
        all_entries = [e for e in all_entries if e["mac"] == search_mac]
        if not all_entries:
            print(f"MAC {search_mac} not found on any queried device.")
            sys.exit(0)

    if args.vlan:
        all_entries = [e for e in all_entries if e["vlan"] == args.vlan]

    if args.output:
        write_csv(all_entries, args.output)
    else:
        print_table(all_entries)


if __name__ == "__main__":
    main()
```