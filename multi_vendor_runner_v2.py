mac_locator.py - MAC Address Location Finder

Purpose:
    Connects to one or more network switches and searches the MAC address table
    to locate which port and VLAN a given MAC address is currently active on.
    Useful for tracking down rogue devices, auditing port assignments, and
    troubleshooting layer-2 connectivity issues.

    Supports Cisco IOS, IOS-XE, NX-OS, and Arista EOS.

Usage:
    # Single device
    python mac_locator.py -d 192.168.1.1 -u admin -p secret -m aa:bb:cc:dd:ee:ff

    # Multiple devices from file (one IP/hostname per line, # for comments)
    python mac_locator.py -f devices.txt -u admin -p secret -m aabb.ccdd.eeff

    # Explicit device type
    python mac_locator.py -d 10.0.0.1 -u admin -p secret -m aabbccddeeff \
        --device-type cisco_nxos

Prerequisites:
    pip install netmiko
    SSH enabled on target devices
    Read-only credentials are sufficient (show commands only)

Exit codes:
    0 - MAC address found on at least one device
    1 - MAC address not found, or fatal argument error
"""

import argparse
import logging
import re
import sys
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

VENDOR_COMMANDS = {
    "cisco_ios": "show mac address-table",
    "cisco_xe": "show mac address-table",
    "cisco_nxos": "show mac address-table",
    "arista_eos": "show mac address-table",
}

# Each pattern captures: (vlan, mac, interface)
MAC_PATTERNS = {
    "cisco_ios": r"^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+\S+\s+(\S+)",
    "cisco_nxos": r"^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+\S+\s+\S+\s+(\S+)",
    "arista_eos": r"^\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+\S+\s+(\S+)",
}


def normalize_mac(mac: str) -> str:
    """Convert any common MAC format to Cisco dotted-quad (aabb.ccdd.eeff)."""
    cleaned = re.sub(r"[:\-\.]", "", mac).lower()
    if len(cleaned) != 12 or not re.fullmatch(r"[0-9a-f]{12}", cleaned):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return f"{cleaned[:4]}.{cleaned[4:8]}.{cleaned[8:]}"


def find_mac_on_device(
    host: str,
    username: str,
    password: str,
    device_type: str,
    target_mac: str,
    port: int = 22,
) -> Optional[dict]:
    """SSH to device and search MAC table. Returns match dict or None."""
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "timeout": 15,
    }

    try:
        log.info("Connecting to %s (%s)", host, device_type)
        with ConnectHandler(**params) as conn:
            cmd = VENDOR_COMMANDS.get(device_type, "show mac address-table")
            output = conn.send_command(cmd)
    except AuthenticationException:
        log.error("Authentication failed: %s", host)
        return None
    except NetmikoTimeoutException:
        log.error("Timeout connecting to %s", host)
        return None
    except Exception as exc:
        log.error("Error on %s: %s", host, exc)
        return None

    pattern_key = device_type if device_type in MAC_PATTERNS else "cisco_ios"
    pattern = MAC_PATTERNS[pattern_key]

    for line in output.splitlines():
        m = re.match(pattern, line, re.IGNORECASE)
        if not m:
            continue
        vlan, found_mac, interface = m.group(1), m.group(2), m.group(3)
        if found_mac.lower() == target_mac:
            return {"host": host, "vlan": vlan, "interface": interface, "mac": found_mac}

    log.debug("MAC %s not in table on %s", target_mac, host)
    return None


def load_devices(path: str) -> list:
    try:
        with open(path) as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except FileNotFoundError:
        log.error("Device file not found: %s", path)
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Locate a MAC address across one or more network switches."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-d", "--device", help="Single device IP or hostname")
    source.add_argument("-f", "--file", help="File listing device IPs/hostnames, one per line")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("-m", "--mac", required=True, help="MAC address to locate")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(VENDOR_COMMANDS.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug output")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        target_mac = normalize_mac(args.mac)
    except ValueError as exc:
        log.error("%s", exc)
        sys.exit(1)

    log.info("Searching for MAC: %s", target_mac)
    devices = [args.device] if args.device else load_devices(args.file)

    found = False
    for host in devices:
        result = find_mac_on_device(
            host=host,
            username=args.username,
            password=args.password,
            device_type=args.device_type,
            target_mac=target_mac,
            port=args.port,
        )
        if result:
            print(
                f"FOUND  host={result['host']}  vlan={result['vlan']}"
                f"  interface={result['interface']}  mac={result['mac']}"
            )
            found = True

    if not found:
        log.warning("MAC %s not found on any queried device", target_mac)
        sys.exit(1)