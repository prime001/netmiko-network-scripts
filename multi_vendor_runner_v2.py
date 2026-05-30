MAC Address Locator — find which switchport a MAC address is learned on.

Connects to one or more switches in parallel, queries the MAC address table,
and reports which port the target MAC is associated with.

Usage:
    python mac_locator.py -d 10.0.0.1 10.0.0.2 -m aa:bb:cc:dd:ee:ff -p secret
    python mac_locator.py -f switches.txt -m aabb.ccdd.eeff -u admin -p secret
    python mac_locator.py -d 10.0.0.1 -m 00-1A-2B-3C-4D-5E -p secret -e enable_pw

    Device file format (one per line):
        10.0.0.1
        10.0.0.2 cisco_nxos

Prerequisites:
    pip install netmiko
    SSH access with sufficient privileges to read the MAC address table.

Supported device types: cisco_ios, cisco_xe, cisco_nxos, aruba_os, hp_comware
"""

import argparse
import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

MAC_COMMANDS = {
    "cisco_ios": "show mac address-table",
    "cisco_xe": "show mac address-table",
    "cisco_nxos": "show mac address-table",
    "aruba_os": "show mac-address-table",
    "hp_comware": "display mac-address",
}

_MAC_RE = re.compile(
    r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}"
    r"|[0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5})"
    r".+?"
    r"((?:Gi|Fa|Te|Tw|Hu|Eth|Po|GigabitEthernet|FastEthernet"
    r"|TenGigabitEthernet|Port-channel|Vlan)\S+)",
    re.IGNORECASE,
)


def normalize_mac(mac: str) -> str:
    return re.sub(r"[.:\-]", "", mac).lower()


def search_device(host: str, device_type: str, username: str, password: str,
                  target_mac: str, secret: str = "") -> dict:
    result = {"host": host, "found": False, "port": None, "error": None}
    command = MAC_COMMANDS.get(device_type, "show mac address-table")

    try:
        params = {"device_type": device_type, "host": host,
                  "username": username, "password": password}
        if secret:
            params["secret"] = secret

        with ConnectHandler(**params) as conn:
            if secret:
                conn.enable()
            output = conn.send_command(command)

        for line in output.splitlines():
            m = _MAC_RE.search(line)
            if m and normalize_mac(m.group(1)) == target_mac:
                result["found"] = True
                result["port"] = m.group(2)
                break

    except NetmikoAuthenticationException:
        result["error"] = "authentication failed"
    except NetmikoTimeoutException:
        result["error"] = "connection timed out"
    except Exception as exc:
        result["error"] = str(exc)

    return result


def load_devices(hosts: list, device_file: str, default_type: str) -> list:
    devices = [{"host": h, "device_type": default_type} for h in (hosts or [])]

    if device_file:
        try:
            with open(device_file) as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    devices.append({
                        "host": parts[0],
                        "device_type": parts[1] if len(parts) > 1 else default_type,
                    })
        except FileNotFoundError:
            logger.error("Device file not found: %s", device_file)
            sys.exit(1)

    return devices


def main():
    parser = argparse.ArgumentParser(
        description="Locate a MAC address across one or more switches."
    )
    parser.add_argument("-d", "--devices", nargs="+", metavar="HOST",
                        help="Switch IPs or hostnames")
    parser.add_argument("-f", "--file", metavar="FILE",
                        help="File listing devices (host [device_type], one per line)")
    parser.add_argument("-m", "--mac", required=True,
                        help="MAC address to locate (any common format)")
    parser.add_argument("-u", "--username", default="admin", help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("-e", "--enable", default="", metavar="SECRET",
                        help="Enable/privilege secret")
    parser.add_argument("-t", "--device-type", default="cisco_ios",
                        choices=list(MAC_COMMANDS),
                        help="Default netmiko device type (default: cisco_ios)")
    parser.add_argument("-w", "--workers", type=int, default=10,
                        help="Parallel threads (default: 10)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.devices and not args.file:
        parser.error("Specify at least one device via -d or -f")

    target = normalize_mac(args.mac)
    if len(target) != 12 or not re.fullmatch(r"[0-9a-f]{12}", target):
        parser.error(f"Invalid MAC address: {args.mac!r}")

    devices = load_devices(args.devices, args.file, args.device_type)
    if not devices:
        logger.error("No devices to query.")
        sys.exit(1)

    logger.info("Querying %d device(s) for MAC %s", len(devices), args.mac)

    found_any = False
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                search_device,
                dev["host"], dev["device_type"],
                args.username, args.password,
                target, args.enable,
            ): dev["host"]
            for dev in devices
        }
        for future in as_completed(futures):
            res = future.result()
            if res["error"]:
                logger.warning("[%s] %s", res["host"], res["error"])
            elif res["found"]:
                print(f"[FOUND] {res['host']}  ->  {res['port']}")
                found_any = True
            else:
                logger.info("[%s] not found", res["host"])

    if not found_any:
        print("MAC address not found on any queried device.")
        sys.exit(1)


if __name__ == "__main__":
    main()