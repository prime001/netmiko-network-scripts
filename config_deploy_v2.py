mac_address_tracker.py - Locate a MAC address across network switches.

Purpose:
    Search one or more switches for a specific MAC address, reporting the
    device, VLAN, and interface where the endpoint is connected. Useful for
    troubleshooting connectivity issues, auditing endpoint locations, and
    identifying rogue or unknown devices on the network.

Usage:
    # Single device
    python mac_address_tracker.py --host 192.168.1.1 --username admin \
        --password secret --mac 00:1a:2b:3c:4d:5e

    # Multiple devices from file (one IP/hostname per line)
    python mac_address_tracker.py --hosts-file switches.txt --username admin \
        --password secret --mac 001a.2b3c.4d5e --device-type cisco_ios

Prerequisites:
    pip install netmiko
    SSH must be enabled on target devices.
    Supported device types: cisco_ios, cisco_ios_xe, cisco_nxos
"""

import argparse
import logging
import re
import sys
from pathlib import Path

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def normalize_mac(mac: str) -> str:
    """Return lowercase 12-hex-char string, raising ValueError on bad input."""
    cleaned = re.sub(r"[:\.\-]", "", mac).lower()
    if len(cleaned) != 12 or not re.fullmatch(r"[0-9a-f]{12}", cleaned):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return cleaned


def to_cisco_dotted(mac: str) -> str:
    """Convert normalized MAC to Cisco dotted quad (xxxx.xxxx.xxxx)."""
    m = normalize_mac(mac)
    return f"{m[0:4]}.{m[4:8]}.{m[8:12]}"


def parse_mac_table(output: str, target_mac: str) -> list:
    """
    Extract rows matching target_mac from show mac address-table output.
    Returns list of dicts with keys: vlan, mac, interface.
    Handles IOS (DYNAMIC/STATIC column) and NX-OS (age column) formats.
    """
    target_norm = normalize_mac(target_mac)
    results = []
    # IOS:   10  0050.7966.6800  DYNAMIC     Gi0/1
    # NX-OS: 10    0050.7966.6800   dynamic    Eth1/1
    pattern = re.compile(
        r"^\s*(\d+)\s+([\da-fA-F]{4}\.[\da-fA-F]{4}\.[\da-fA-F]{4})"
        r"\s+\S+\s+(\S+)",
        re.MULTILINE,
    )
    for match in pattern.finditer(output):
        vlan, mac_field, interface = match.groups()
        if normalize_mac(mac_field) == target_norm:
            results.append({"vlan": vlan, "mac": mac_field, "interface": interface})
    return results


def search_device(host: str, username: str, password: str, device_type: str,
                  target_mac: str, port: int = 22) -> dict:
    """Connect to one device and return MAC search results."""
    result = {"host": host, "status": "error", "matches": [], "error": None}
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "timeout": 30,
        "banner_timeout": 15,
    }
    try:
        logger.info("Connecting to %s", host)
        with ConnectHandler(**params) as conn:
            cisco_mac = to_cisco_dotted(target_mac)
            # Targeted lookup first — faster and less output to parse
            output = conn.send_command(
                f"show mac address-table address {cisco_mac}",
                read_timeout=30,
            )
            matches = parse_mac_table(output, target_mac)
            if not matches:
                # Fallback for platforms that don't support address filter
                logger.debug("Targeted lookup empty on %s, scanning full table", host)
                output = conn.send_command(
                    "show mac address-table", read_timeout=60
                )
                matches = parse_mac_table(output, target_mac)
            result["status"] = "success"
            result["matches"] = matches
    except NetmikoAuthenticationException:
        result["error"] = "authentication failed"
        logger.error("Auth failed: %s", host)
    except NetmikoTimeoutException:
        result["error"] = "connection timed out"
        logger.error("Timeout: %s", host)
    except Exception as exc:
        result["error"] = str(exc)
        logger.error("Error on %s: %s", host, exc)
    return result


def load_hosts_file(path: str) -> list:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Hosts file not found: {path}")
    return [
        line.strip()
        for line in p.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


def main():
    parser = argparse.ArgumentParser(
        description="Locate a MAC address across one or more network switches",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit codes: 0=found, 1=error, 2=not found on any device",
    )
    host_group = parser.add_mutually_exclusive_group(required=True)
    host_group.add_argument("--host", help="Single switch IP or hostname")
    host_group.add_argument(
        "--hosts-file", metavar="FILE", help="File containing one host per line"
    )
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument(
        "--mac", required=True,
        help="MAC address to locate (accepts xx:xx:xx:xx:xx:xx, xxxx.xxxx.xxxx, etc.)",
    )
    parser.add_argument(
        "--device-type", default="cisco_ios",
        choices=["cisco_ios", "cisco_ios_xe", "cisco_nxos"],
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument(
        "--port", type=int, default=22, help="SSH port (default: 22)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable debug logging"
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        normalize_mac(args.mac)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        hosts = [args.host] if args.host else load_hosts_file(args.hosts_file)
    except FileNotFoundError as exc:
        parser.error(str(exc))

    if not hosts:
        logger.error("No hosts to search")
        sys.exit(1)

    logger.info("Searching for MAC %s on %d device(s)", args.mac, len(hosts))

    found = False
    errors = 0
    for host in hosts:
        result = search_device(
            host=host,
            username=args.username,
            password=args.password,
            device_type=args.device_type,
            target_mac=args.mac,
            port=args.port,
        )
        if result["status"] == "error":
            print(f"[ERROR]     {host}: {result['error']}")
            errors += 1
            continue
        if result["matches"]:
            found = True
            for m in result["matches"]:
                print(
                    f"[FOUND]     {host} | VLAN {m['vlan']:>4} | "
                    f"{m['interface']:<20} | {m['mac']}"
                )
        else:
            print(f"[NOT FOUND] {host}")

    if errors and not found:
        sys.exit(1)
    if not found:
        logger.info("MAC %s not present on any queried device", args.mac)
        sys.exit(2)


if __name__ == "__main__":
    main()