```python
"""
mac_locator.py - MAC Address Table Lookup Tool

Connects to one or more switches and searches the MAC address table for a given
MAC address or OUI prefix. Useful for locating end-hosts, tracking down rogue
devices, and auditing port-to-host mappings across a fleet.

Usage:
    python mac_locator.py --host 192.168.1.1 --username admin --password secret \\
        --mac aa:bb:cc:dd:ee:ff

    python mac_locator.py --host 192.168.1.1 --username admin --password secret \\
        --mac aa:bb:cc --partial

    python mac_locator.py --hosts-file switches.txt --username admin \\
        --password secret --mac aa:bb:cc:dd:ee:ff

    Hosts file format: one entry per line as "host [device_type]"
    Lines beginning with # are ignored.

Prerequisites:
    pip install netmiko
"""

import argparse
import logging
import re
import sys
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

VENDOR_COMMANDS = {
    "cisco_ios": "show mac address-table",
    "cisco_nxos": "show mac address-table",
    "cisco_xe": "show mac address-table",
    "arista_eos": "show mac address-table",
    "juniper_junos": "show ethernet-switching table",
    "hp_comware": "display mac-address",
    "hp_procurve": "show mac-address",
}

_MAC_SEPARATORS = re.compile(r"[:\-\.]")


def normalize_mac(mac: str) -> str:
    return _MAC_SEPARATORS.sub("", mac).lower()


def search_mac_in_output(output: str, target: str, partial: bool) -> list:
    matches = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if target in normalize_mac(stripped):
            if partial or len(target) == 12:
                matches.append(stripped)
    return matches


def lookup_mac(host, device_type, username, password, target_mac,
               partial, port=22, secret=""):
    result = {"host": host, "matches": [], "error": None}
    command = VENDOR_COMMANDS.get(device_type, "show mac address-table")

    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "secret": secret,
        "timeout": 15,
    }

    try:
        logger.info("Connecting to %s (%s)", host, device_type)
        with ConnectHandler(**params) as conn:
            if secret:
                conn.enable()
            output = conn.send_command(command, read_timeout=20)
        result["matches"] = search_mac_in_output(output, target_mac, partial)
        logger.info("%s: %d match(es)", host, len(result["matches"]))
    except NetmikoAuthenticationException:
        result["error"] = "authentication failed"
        logger.error("%s: authentication failed", host)
    except NetmikoTimeoutException:
        result["error"] = "connection timed out"
        logger.error("%s: timed out", host)
    except Exception as exc:
        result["error"] = str(exc)
        logger.error("%s: %s", host, exc)

    return result


def load_hosts(args):
    hosts = []
    if args.host:
        hosts.append({"host": args.host, "device_type": args.device_type})
    else:
        path = Path(args.hosts_file)
        if not path.exists():
            logger.error("Hosts file not found: %s", args.hosts_file)
            sys.exit(1)
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            hosts.append({
                "host": parts[0],
                "device_type": parts[1] if len(parts) > 1 else args.device_type,
            })
    return hosts


def parse_args():
    parser = argparse.ArgumentParser(
        description="Search MAC address tables across one or more switches.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--host", help="Single device IP or hostname")
    target.add_argument("--hosts-file", metavar="FILE",
                        help="File listing hosts, one per line (host [device_type])")
    parser.add_argument("--device-type", default="cisco_ios",
                        choices=list(VENDOR_COMMANDS.keys()),
                        help="Netmiko device type")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--secret", default="", help="Enable/privilege secret")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--mac", required=True,
                        help="MAC address or OUI to find (any separator format)")
    parser.add_argument("--partial", action="store_true",
                        help="Match MAC as a substring (e.g. OUI-only search)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    target_mac = normalize_mac(args.mac)
    if not args.partial and len(target_mac) != 12:
        logger.error(
            "MAC '%s' normalizes to %d hex chars; use --partial for prefix searches",
            args.mac, len(target_mac),
        )
        sys.exit(1)

    hosts = load_hosts(args)
    if not hosts:
        logger.error("No hosts to query.")
        sys.exit(1)

    found_on = []
    errors = []

    for entry in hosts:
        result = lookup_mac(
            host=entry["host"],
            device_type=entry["device_type"],
            username=args.username,
            password=args.password,
            target_mac=target_mac,
            partial=args.partial,
            port=args.port,
            secret=args.secret,
        )
        if result["error"]:
            errors.append(result["host"])
            print(f"[ERROR]     {result['host']}: {result['error']}")
        elif result["matches"]:
            found_on.append(result["host"])
            print(f"[FOUND]     {result['host']}:")
            for line in result["matches"]:
                print(f"            {line}")
        else:
            print(f"[NOT FOUND] {result['host']}")

    print(
        f"\nSummary: searched {len(hosts)} device(s), "
        f"found on {len(found_on)}, "
        f"{len(errors)} error(s)."
    )
    sys.exit(0 if found_on else 1)


if __name__ == "__main__":
    main()
```