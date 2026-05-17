interface_error_monitor.py — Interface Error Counter Monitor

Purpose:
    Connects to a network device via SSH, collects per-interface error counters
    (input errors, CRC, output drops, giants, runts), and reports any interface
    exceeding a configurable threshold. Useful for identifying degraded links or
    faulty hardware before they cause outages.

Usage:
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -d 10.0.0.1 -u admin -p secret --threshold 50 --json
    python interface_error_monitor.py -d 10.0.0.1 -u admin -p secret --device-type cisco_nxos --all

Prerequisites:
    pip install netmiko
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass
from typing import List, Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class InterfaceErrors:
    name: str
    input_errors: int = 0
    crc: int = 0
    output_drops: int = 0
    giants: int = 0
    runts: int = 0

    def flagged(self, threshold: int) -> bool:
        return (
            self.input_errors >= threshold
            or self.crc >= threshold
            or self.output_drops >= threshold
        )

    def severity_score(self) -> int:
        return self.input_errors + self.output_drops + self.crc

    def to_dict(self) -> dict:
        return {
            "interface": self.name,
            "input_errors": self.input_errors,
            "crc": self.crc,
            "output_drops": self.output_drops,
            "giants": self.giants,
            "runts": self.runts,
        }


def parse_interface_errors(output: str) -> List[InterfaceErrors]:
    interfaces: List[InterfaceErrors] = []
    current: Optional[InterfaceErrors] = None

    intf_re = re.compile(r"^(\S+)\s+is\s+(?:up|down|administratively down)")
    input_err_re = re.compile(r"(\d+)\s+input errors")
    crc_re = re.compile(r"(\d+)\s+CRC")
    output_drop_re = re.compile(r"(\d+)\s+output drops")
    output_queue_re = re.compile(r"[Oo]utput queue[^,]*,\s*(\d+)\s+drops")
    giants_re = re.compile(r"(\d+)\s+giants")
    runts_re = re.compile(r"(\d+)\s+runts")

    for line in output.splitlines():
        if m := intf_re.match(line):
            if current is not None:
                interfaces.append(current)
            current = InterfaceErrors(name=m.group(1))
            continue

        if current is None:
            continue

        if m := input_err_re.search(line):
            current.input_errors = int(m.group(1))
        if m := crc_re.search(line):
            current.crc = int(m.group(1))
        if m := output_drop_re.search(line):
            current.output_drops = int(m.group(1))
        if m := output_queue_re.search(line):
            current.output_drops = max(current.output_drops, int(m.group(1)))
        if m := giants_re.search(line):
            current.giants = int(m.group(1))
        if m := runts_re.search(line):
            current.runts = int(m.group(1))

    if current is not None:
        interfaces.append(current)

    return interfaces


def collect_errors(
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

    log.info("Connecting to %s (%s)", host, device_type)
    with ConnectHandler(**params) as conn:
        if enable_secret:
            conn.enable()
        raw = conn.send_command("show interfaces", read_timeout=60)

    interfaces = parse_interface_errors(raw)
    log.info("Parsed %d interfaces from %s", len(interfaces), host)
    return interfaces


def print_table(interfaces: List[InterfaceErrors], threshold: int, show_all: bool) -> None:
    target = interfaces if show_all else [i for i in interfaces if i.flagged(threshold)]

    if not target:
        print(f"\nAll {len(interfaces)} interfaces are within threshold ({threshold}). No errors detected.\n")
        return

    col = [32, 14, 10, 14, 8, 8]
    total_w = sum(col)
    header = (
        f"{'Interface':<{col[0]}} {'Input Errors':>{col[1]}} {'CRC':>{col[2]}} "
        f"{'Output Drops':>{col[3]}} {'Giants':>{col[4]}} {'Runts':>{col[5]}}"
    )

    label = "ALL INTERFACES" if show_all else f"FLAGGED INTERFACES (threshold={threshold})"
    print(f"\n{label:^{total_w}}")
    print("-" * total_w)
    print(header)
    print("-" * total_w)

    for intf in sorted(target, key=lambda x: x.severity_score(), reverse=True):
        flag = " !" if intf.flagged(threshold) else "  "
        print(
            f"{intf.name:<{col[0]}} {intf.input_errors:>{col[1]}} {intf.crc:>{col[2]}} "
            f"{intf.output_drops:>{col[3]}} {intf.giants:>{col[4]}} {intf.runts:>{col[5]}}{flag}"
        )

    flagged_count = sum(1 for i in interfaces if i.flagged(threshold))
    print(f"\n{flagged_count}/{len(interfaces)} interface(s) flagged.\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Report interface error counters and flag degraded links."
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("-e", "--enable-secret", default=None, help="Enable/privilege password")
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--threshold",
        type=int,
        default=10,
        help="Error count to flag an interface (default: 10)",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Output flagged interfaces as JSON",
    )
    p.add_argument(
        "--all",
        action="store_true",
        dest="show_all",
        help="Include interfaces with zero errors in output",
    )
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        interfaces = collect_errors(
            host=args.device,
            username=args.username,
            password=args.password,
            device_type=args.device_type,
            port=args.port,
            enable_secret=args.enable_secret,
        )
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.device)
        sys.exit(1)
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        sys.exit(1)

    if args.json:
        flagged = interfaces if args.show_all else [i for i in interfaces if i.flagged(args.threshold)]
        print(json.dumps(
            {"device": args.device, "threshold": args.threshold, "interfaces": [i.to_dict() for i in flagged]},
            indent=2,
        ))
    else:
        print_table(interfaces, args.threshold, args.show_all)