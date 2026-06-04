The file was blocked by permissions. The script content is ready — here it is:

```python
"""
mac_port_locator.py - Locate a device's switch port by IP or MAC address.

Purpose:
    Given a target IP or MAC address, connects to a Cisco IOS/IOS-XE switch,
    resolves the MAC via ARP table if needed, then traces it through the MAC
    address table to identify the physical access port and its description.

Usage:
    python mac_port_locator.py --host 10.0.0.1 --username admin --password secret \
        --target 192.168.1.50
    python mac_port_locator.py --host 10.0.0.1 --username admin --password secret \
        --target aa:bb:cc:dd:ee:ff --vlan 100
    python mac_port_locator.py --host 10.0.0.1 --username admin --password secret \
        --target 192.168.1.50 --device-type cisco_ios --secret enable_pw

Prerequisites:
    pip install netmiko
    Netmiko >= 4.0 recommended.
    Device must support: show ip arp, show mac address-table.
    SSH credentials require at minimum read-only (show) access.
"""

import argparse
import logging
import re
import sys
from typing import Dict, List, Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def normalize_mac(mac: str) -> str:
    """Normalize any common MAC format to Cisco dotted-quad (e.g. aabb.ccdd.eeff)."""
    clean = re.sub(r"[:\-\.\s]", "", mac).lower()
    if len(clean) != 12 or not re.fullmatch(r"[0-9a-f]{12}", clean):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return f"{clean[0:4]}.{clean[4:8]}.{clean[8:12]}"


def resolve_ip_to_mac(conn, ip: str) -> Optional[str]:
    """Return the MAC address for an IP from the device ARP table, or None."""
    output = conn.send_command(f"show ip arp {ip}")
    match = re.search(
        r"Internet\s+" + re.escape(ip) + r"\s+\S+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})",
        output,
        re.IGNORECASE,
    )
    return match.group(1).lower() if match else None


def find_mac_in_table(conn, mac: str, vlan: Optional[str]) -> List[Dict[str, str]]:
    """Query the MAC address table and return all matching entries."""
    cmd = f"show mac address-table address {mac}"
    if vlan:
        cmd = f"show mac address-table vlan {vlan} address {mac}"
    output = conn.send_command(cmd)

    entries = []
    for line in output.splitlines():
        # Matches Cisco IOS/IOS-XE: vlan  mac  type  port
        m = re.match(
            r"\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\S+)\s+(\S+)",
            line,
            re.IGNORECASE,
        )
        if m:
            entries.append({
                "vlan": m.group(1),
                "mac": m.group(2).lower(),
                "type": m.group(3),
                "port": m.group(4),
            })
    return entries


def get_port_description(conn, port: str) -> str:
    """Return the configured description for an interface, or empty string."""
    output = conn.send_command(f"show interface {port}")
    m = re.search(r"Description:\s+(.+)", output)
    return m.group(1).strip() if m else ""


def is_uplink_port(port: str) -> bool:
    """Heuristic: high-speed interfaces are typically uplinks/trunks, not access ports."""
    uplink_prefixes = ("Te", "TenGig", "Fo", "FortyGig", "Hu", "HundredGig", "Po")
    return any(port.startswith(p) for p in uplink_prefixes)


def locate_device(conn, target: str, vlan: Optional[str]) -> Dict:
    result = {
        "target": target,
        "mac": None,
        "vlan": None,
        "port": None,
        "description": None,
        "warning": None,
    }

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        logger.info("Resolving IP %s to MAC via ARP table", target)
        mac = resolve_ip_to_mac(conn, target)
        if not mac:
            result["warning"] = f"IP {target} not found in ARP table — device may be offline or unreachable from this switch"
            return result
        result["mac"] = mac
    else:
        try:
            mac = normalize_mac(target)
        except ValueError as exc:
            result["warning"] = str(exc)
            return result
        result["mac"] = mac

    logger.info("Searching MAC address table for %s", mac)
    entries = find_mac_in_table(conn, mac, vlan)

    if not entries:
        result["warning"] = f"MAC {mac} not found in address table — device may have aged out or be on a different switch"
        return result

    # Prefer non-uplink entries; device may appear on multiple ports in a stack
    access_entries = [e for e in entries if not is_uplink_port(e["port"])]
    chosen = access_entries[0] if access_entries else entries[0]

    result["vlan"] = chosen["vlan"]
    result["port"] = chosen["port"]
    result["description"] = get_port_description(conn, chosen["port"])

    if not access_entries:
        result["warning"] = "Only uplink/trunk ports found — device is likely behind another switch"

    return result


def print_result(result: Dict) -> None:
    print("\n=== MAC Port Locator Results ===")
    print(f"  Target      : {result['target']}")
    if result["mac"]:
        print(f"  MAC Address : {result['mac']}")
    if result["vlan"]:
        print(f"  VLAN        : {result['vlan']}")
    if result["port"]:
        print(f"  Switch Port : {result['port']}")
    if result["description"]:
        print(f"  Port Desc   : {result['description']}")
    if result["warning"]:
        print(f"  WARNING     : {result['warning']}")
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Locate a device's physical switch port by IP or MAC address.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", required=True, help="Switch IP address or hostname")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument("--secret", default="", help="Enable/privileged mode secret")
    parser.add_argument(
        "--target", required=True,
        help="Target IP address or MAC address to locate"
    )
    parser.add_argument(
        "--vlan", default=None,
        help="Restrict MAC table lookup to a specific VLAN ID"
    )
    parser.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)"
    )
    parser.add_argument(
        "--port", type=int, default=22,
        help="SSH port (default: 22)"
    )
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "secret": args.secret,
        "port": args.port,
    }

    logger.info("Connecting to %s", args.host)
    try:
        with ConnectHandler(**device) as conn:
            if args.secret:
                conn.enable()
            result = locate_device(conn, args.target, args.vlan)
    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s", args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        logger.error("Connection timed out to %s", args.host)
        sys.exit(1)
    except Exception as exc:
        logger.error("Unexpected error: %s", exc)
        sys.exit(1)

    print_result(result)
    sys.exit(0 if result["port"] else 1)
```

**What this does:** `mac_port_locator.py` — a MAC-to-port tracer that:
- Accepts either an IP address or MAC address as the target
- If given an IP, resolves it to MAC via `show ip arp`
- Normalizes any MAC format (colon, dash, dotted-quad) to Cisco format
- Looks up the MAC in `show mac address-table`, with optional VLAN filter
- Heuristically distinguishes access ports from uplinks (TenGig, PortChannel, etc.) and prefers the access port
- Fetches the port's configured description for context
- Exits 0 on success, 1 on failure (CI-friendly)

This is distinct from the existing `device_discovery.py` scripts, which find devices on the network — this finds *where* a specific device is physically connected.