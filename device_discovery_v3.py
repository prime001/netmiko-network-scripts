The request asks for plain script output only — here it is:

```
"""
mac_tracker.py - MAC Address Location Tracker

Purpose:
    Locate one or more MAC addresses across a set of switches by querying
    each device's MAC address table.  Useful for finding which switchport a
    workstation or server is connected to, tracking down rogue devices, or
    confirming post-migration connectivity without needing SNMP or a full NMS.

Usage:
    # Locate two MACs across three switches
    python mac_tracker.py -d 10.0.0.1 10.0.0.2 10.0.0.3 \
        -u admin -p secret \
        -m aa:bb:cc:dd:ee:ff 00:11:22:33:44:55

    # Prompt for password interactively
    python mac_tracker.py -d 192.168.1.1 -u admin --ask-pass \
        -m aabb.ccdd.eeff --device-type cisco_ios

    # Increase timeout for slow devices and enable debug output
    python mac_tracker.py -d 10.1.1.1 -u admin -p secret \
        -m 0011.2233.4455 --timeout 60 -v

Prerequisites:
    pip install netmiko
    SSH reachable on port 22; read-only credentials are sufficient.
    Tested with Cisco IOS / IOS-XE; --device-type accepts any netmiko type.
"""

import argparse
import getpass
import logging
import re
import sys
from dataclasses import dataclass
from typing import Optional

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def normalize_mac(mac: str) -> str:
    """Strip delimiters and return lowercase 12-char hex string."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(cleaned) != 12:
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return cleaned.lower()


def parse_mac_table(output: str, targets: set) -> list:
    """
    Parse 'show mac address-table' for Cisco IOS/IOS-XE.

    Returns list of dicts: {vlan, mac, type, interface} for target MACs only.
    """
    results = []
    pattern = re.compile(
        r"^\s*(\d+)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})"
        r"\s+(\S+)\s+(\S+)",
        re.MULTILINE,
    )
    for match in pattern.finditer(output):
        vlan, raw_mac, entry_type, interface = match.groups()
        if normalize_mac(raw_mac) in targets:
            results.append(
                {"vlan": vlan, "mac": raw_mac, "type": entry_type, "interface": interface}
            )
    return results


def parse_descriptions(output: str) -> dict:
    """Return {interface: description} from 'show interfaces description'."""
    desc_map = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.match(r"^[A-Za-z]", parts[0]):
            desc = " ".join(parts[3:]) if len(parts) > 3 else ""
            desc_map[parts[0]] = desc
    return desc_map


@dataclass
class SearchResult:
    device: str
    mac: str
    vlan: str
    interface: str
    entry_type: str
    description: str = ""
    error: Optional[str] = None


def query_device(host: str, conn_params: dict, targets: set) -> list:
    results = []
    try:
        logger.info("Connecting to %s", host)
        with ConnectHandler(**conn_params) as conn:
            mac_output = conn.send_command("show mac address-table")
            matches = parse_mac_table(mac_output, targets)

            if not matches:
                return results

            desc_output = conn.send_command("show interfaces description")
            desc_map = parse_descriptions(desc_output)

            for entry in matches:
                iface = entry["interface"]
                results.append(
                    SearchResult(
                        device=host,
                        mac=entry["mac"],
                        vlan=entry["vlan"],
                        interface=iface,
                        entry_type=entry["type"],
                        description=desc_map.get(iface, ""),
                    )
                )
    except NetmikoAuthenticationException:
        results.append(
            SearchResult(device=host, mac="", vlan="", interface="",
                         entry_type="", error="Authentication failed")
        )
    except NetmikoTimeoutException:
        results.append(
            SearchResult(device=host, mac="", vlan="", interface="",
                         entry_type="", error="Connection timed out")
        )
    except Exception as exc:
        results.append(
            SearchResult(device=host, mac="", vlan="", interface="",
                         entry_type="", error=str(exc))
        )
    return results


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Locate MAC addresses across network switches via SSH",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="MAC format: any delimiter style accepted (colons, dots, dashes, or bare hex)",
    )
    p.add_argument("-d", "--devices", nargs="+", required=True, metavar="HOST",
                   help="Switch IP(s) or hostnames to query")
    p.add_argument("-m", "--macs", nargs="+", required=True, metavar="MAC",
                   help="MAC address(es) to locate")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password")
    p.add_argument("--ask-pass", action="store_true",
                   help="Prompt for password (overrides -p)")
    p.add_argument("--device-type", default="cisco_ios",
                   help="Netmiko device type (default: cisco_ios)")
    p.add_argument("--timeout", type=int, default=30,
                   help="SSH connection timeout in seconds (default: 30)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Enable debug logging")
    return p


def main() -> int:
    parser = build_argparser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if args.ask_pass or password is None:
        password = getpass.getpass(f"Password for {args.username}@<devices>: ")

    try:
        targets = {normalize_mac(m) for m in args.macs}
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    conn_base = {
        "device_type": args.device_type,
        "username": args.username,
        "password": password,
        "timeout": args.timeout,
    }

    all_results = []
    for host in args.devices:
        print(f"Querying {host} ...", end=" ", flush=True)
        found = query_device(host, {**conn_base, "host": host}, targets)
        hits = [r for r in found if not r.error]
        errors = [r for r in found if r.error]
        print(f"{len(hits)} hit(s)" + (f", {len(errors)} error(s)" if errors else ""))
        all_results.extend(found)

    errors = [r for r in all_results if r.error]
    hits = [r for r in all_results if not r.error]

    if errors:
        print("\n=== Errors ===")
        for r in errors:
            print(f"  {r.device}: {r.error}")

    if not hits:
        print("\nNo matching MAC addresses found across queried devices.")
        return 0

    col = "{:<20} {:<18} {:<6} {:<22} {:<10} {}"
    print(f"\n{col.format('Device', 'MAC', 'VLAN', 'Interface', 'Type', 'Description')}")
    print("-" * 94)
    for r in sorted(hits, key=lambda x: (x.mac, x.device)):
        print(col.format(r.device, r.mac, r.vlan, r.interface, r.entry_type, r.description))

    return 0


if __name__ == "__main__":
    sys.exit(main())
```