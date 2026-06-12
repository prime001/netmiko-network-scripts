The script is ready. Here's the content (copy/paste it as `mac_table_search.py`):

```python
"""
mac_table_search.py - Search MAC address tables to locate a device on the network.

Purpose:
    Connects to one or more Cisco IOS/IOS-XE switches and searches the MAC address
    table for a specific MAC address, or dumps the full table for auditing. Useful
    for quickly pinpointing which port and VLAN a device is connected to during
    troubleshooting, moves/adds/changes, or security investigations.

Usage:
    # Search a single switch for a specific MAC
    python mac_table_search.py --host 10.0.0.1 --username admin --mac 00:1a:2b:3c:4d:5e

    # Search multiple switches listed in a file
    python mac_table_search.py --hosts-file switches.txt --username admin --mac aabb.cc00.1122

    # Dump the full MAC table from a switch
    python mac_table_search.py --host 10.0.0.1 --username admin --all

Prerequisites:
    pip install netmiko
    Cisco IOS or IOS-XE device with SSH enabled and credentials that can run
    'show mac address-table'.
"""

import argparse
import getpass
import logging
import re
import sys
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def normalize_mac(mac: str) -> str:
    """Return 12-char lowercase hex string for any common MAC delimiter format."""
    clean = re.sub(r"[:\-\.]", "", mac).lower()
    if len(clean) != 12 or not re.fullmatch(r"[0-9a-f]{12}", clean):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return clean


def to_cisco_mac(mac: str) -> str:
    """Convert normalized MAC to Cisco dotted-quad notation (aabb.ccdd.eeff)."""
    n = normalize_mac(mac)
    return f"{n[0:4]}.{n[4:8]}.{n[8:12]}"


def parse_mac_table(output: str) -> list:
    """
    Parse 'show mac address-table' output into a list of dicts.
    Handles both IOS and IOS-XE column formats.
    """
    entries = []
    pattern = re.compile(
        r"^\s*(\d+|-)\s+"
        r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
        r"(\S+)\s+"
        r"(\S+)",
        re.MULTILINE,
    )
    for match in pattern.finditer(output):
        vlan, mac, entry_type, interface = match.groups()
        entries.append({
            "vlan": vlan,
            "mac": mac.lower(),
            "type": entry_type,
            "interface": interface,
        })
    return entries


def query_device(
    host: str,
    username: str,
    password: str,
    target_mac: Optional[str],
    device_type: str,
) -> tuple:
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "timeout": 30,
    }
    try:
        with ConnectHandler(**params) as conn:
            if target_mac:
                cmd = f"show mac address-table address {to_cisco_mac(target_mac)}"
            else:
                cmd = "show mac address-table"
            output = conn.send_command(cmd, read_timeout=30)
    except NetmikoAuthenticationException:
        logger.error("%s: authentication failed", host)
        return host, []
    except NetmikoTimeoutException:
        logger.error("%s: connection timed out", host)
        return host, []
    except Exception as exc:
        logger.error("%s: %s", host, exc)
        return host, []

    entries = parse_mac_table(output)
    if target_mac:
        norm = normalize_mac(target_mac)
        entries = [e for e in entries if normalize_mac(e["mac"]) == norm]
    return host, entries


def load_hosts(path: str) -> list:
    with open(path) as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def print_results(host: str, entries: list) -> None:
    count = len(entries)
    print(f"\n{'='*64}")
    print(f"Host: {host}  ({count} entr{'y' if count == 1 else 'ies'})")
    print(f"{'VLAN':<8}{'MAC':<20}{'Type':<12}Interface")
    print(f"{'-'*8}{'-'*20}{'-'*12}{'-'*20}")
    for e in entries:
        print(f"{e['vlan']:<8}{e['mac']:<20}{e['type']:<12}{e['interface']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Search MAC address tables on Cisco IOS/IOS-XE switches.",
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--host", help="Single device IP or hostname")
    target_group.add_argument("--hosts-file", metavar="FILE",
                              help="Text file with one host per line")

    parser.add_argument("--username", required=True)
    parser.add_argument("--password", help="SSH password (prompted if omitted)")

    search_group = parser.add_mutually_exclusive_group(required=True)
    search_group.add_argument("--mac", metavar="MAC",
                              help="MAC address to locate (any delimiter format)")
    search_group.add_argument("--all", action="store_true",
                              help="Dump complete MAC address table")

    parser.add_argument("--device-type", default="cisco_ios",
                        help="Netmiko device type (default: cisco_ios)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable debug-level logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.mac:
        try:
            normalize_mac(args.mac)
        except ValueError as exc:
            parser.error(str(exc))

    password = args.password or getpass.getpass(f"Password for {args.username}: ")
    hosts = [args.host] if args.host else load_hosts(args.hosts_file)

    found_any = False
    for host in hosts:
        host, entries = query_device(
            host=host,
            username=args.username,
            password=password,
            target_mac=args.mac if not args.all else None,
            device_type=args.device_type,
        )
        if entries:
            found_any = True
            print_results(host, entries)
        else:
            status = "not found" if args.mac else "no entries returned"
            print(f"{host}: {status}")

    if args.mac and not found_any:
        sys.exit(1)


if __name__ == "__main__":
    main()
```

**What this does:** Searches MAC address tables on Cisco IOS/IOS-XE switches — either hunting for a specific MAC across one or many devices, or dumping the full table. Common real-world task (finding rogue devices, tracing a workstation to its switchport, auditing VLAN membership). Accepts MACs in any delimiter format (`00:1a:2b`, `aabb.cc00`, `001a2b3c4d5e`) and normalizes before comparing.