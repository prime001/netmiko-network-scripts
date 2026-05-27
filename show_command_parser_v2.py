interface_error_monitor.py - Monitor interface error counters on network devices.

Purpose:
    Connects to a network device via SSH, collects interface error counters
    (input errors, CRC, output drops, giants, runts), and flags interfaces
    exceeding a configurable threshold. Useful for triaging link quality
    degradation before errors escalate into outages.

Usage:
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret \
        --device-type cisco_ios --threshold 100 --output errors.csv --all

Prerequisites:
    pip install netmiko
    SSH access with privilege to run 'show interfaces' (or vendor equivalent).
    Tested against Cisco IOS / IOS-XE. Arista EOS uses the same counter format.
"""

import argparse
import csv
import logging
import re
import sys
from dataclasses import dataclass
from typing import List, Optional

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

_IFACE_HEADER = re.compile(
    r"^(\S+) is (up|down|administratively down)", re.MULTILINE
)
_COUNTERS = {
    "input_errors": re.compile(r"(\d+) input errors"),
    "crc": re.compile(r"(\d+) CRC"),
    "output_drops": re.compile(r"(\d+) output drops"),
    "giants": re.compile(r"(\d+) giants"),
    "runts": re.compile(r"(\d+) runts"),
}


@dataclass
class InterfaceErrors:
    name: str
    input_errors: int = 0
    crc: int = 0
    output_drops: int = 0
    giants: int = 0
    runts: int = 0

    def total(self) -> int:
        return self.input_errors + self.crc + self.output_drops + self.giants + self.runts


def parse_show_interfaces(raw: str) -> List[InterfaceErrors]:
    results: List[InterfaceErrors] = []
    blocks = re.split(r"(?=^\S+\s+is\s+(?:up|down|administratively down))", raw, flags=re.MULTILINE)
    for block in blocks:
        m = _IFACE_HEADER.match(block.strip())
        if not m:
            continue
        iface = InterfaceErrors(name=m.group(1))
        for attr, pattern in _COUNTERS.items():
            hit = pattern.search(block)
            if hit:
                setattr(iface, attr, int(hit.group(1)))
        results.append(iface)
    return results


def fetch_interface_data(
    host: str,
    username: str,
    password: str,
    device_type: str,
    port: int,
    enable_secret: Optional[str],
) -> List[InterfaceErrors]:
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
    }
    if enable_secret:
        params["secret"] = enable_secret

    log.info("Connecting to %s (%s:%d)", host, device_type, port)
    with ConnectHandler(**params) as conn:
        if enable_secret:
            conn.enable()
        log.info("Sending 'show interfaces'")
        raw = conn.send_command("show interfaces", read_timeout=60)

    interfaces = parse_show_interfaces(raw)
    log.info("Parsed %d interfaces", len(interfaces))
    return interfaces


def print_table(interfaces: List[InterfaceErrors]) -> None:
    col = f"{'Interface':<35} {'Input Err':>10} {'CRC':>6} {'Out Drops':>10} {'Giants':>7} {'Runts':>6} {'Total':>7}"
    print(col)
    print("-" * len(col))
    for iface in sorted(interfaces, key=lambda x: x.total(), reverse=True):
        flag = " !" if iface.total() > 0 else ""
        print(
            f"{iface.name:<35} {iface.input_errors:>10} {iface.crc:>6} "
            f"{iface.output_drops:>10} {iface.giants:>7} {iface.runts:>6} "
            f"{iface.total():>7}{flag}"
        )


def write_csv(interfaces: List[InterfaceErrors], path: str) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["interface", "input_errors", "crc", "output_drops", "giants", "runts", "total"])
        for i in interfaces:
            writer.writerow([i.name, i.input_errors, i.crc, i.output_drops, i.giants, i.runts, i.total()])
    log.info("Results written to %s", path)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Report interface error counters from a network device.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("--device-type", default="cisco_ios", help="Netmiko device type (default: cisco_ios)")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--enable-secret", default=None, help="Enable/privileged mode password")
    p.add_argument(
        "--threshold",
        type=int,
        default=1,
        help="Only report interfaces with total errors >= this value (default: 1)",
    )
    p.add_argument("--all", dest="show_all", action="store_true", help="Show all interfaces including zero-error")
    p.add_argument("--output", default=None, metavar="FILE", help="Write results to CSV file")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        interfaces = fetch_interface_data(
            host=args.device,
            username=args.username,
            password=args.password,
            device_type=args.device_type,
            port=args.port,
            enable_secret=args.enable_secret,
        )
    except AuthenticationException:
        log.error("Authentication failed for %s", args.device)
        return 1
    except NetmikoTimeoutException:
        log.error("Connection to %s timed out", args.device)
        return 1
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        return 1

    if not interfaces:
        log.warning("No interfaces parsed — verify device type or SSH output")
        return 1

    visible = interfaces if args.show_all else [i for i in interfaces if i.total() >= args.threshold]

    if not visible:
        print(f"No interfaces with error count >= {args.threshold}")
    else:
        print_table(visible)

    if args.output:
        write_csv(visible, args.output)

    flagged = [i for i in interfaces if i.total() >= args.threshold]
    if flagged:
        log.warning("%d interface(s) exceed threshold of %d errors", len(flagged), args.threshold)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())