```
"""
010_interface_stats.py — Interface Statistics Parser

Purpose:
    Connect to a Cisco IOS/IOS-XE device, collect 'show interfaces' output,
    and parse it into structured data (interface state, utilization, and error
    counters). Useful for ad-hoc audits, alerting pipelines, or capacity
    planning exports.

Usage:
    python 010_interface_stats.py --host 192.168.1.1 --username admin \
        [--password SECRET] [--device-type cisco_ios] [--port 22] \
        [--format json|csv] [--filter-errors] [--min-utilization 50]

Prerequisites:
    pip install netmiko
    SSH access to the target device with privilege level >= 1.
"""

import argparse
import csv
import json
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

_INTF_HEADER = re.compile(
    r"^(?P<name>\S+) is (?P<line_status>up|down|administratively down)"
    r".*line protocol is (?P<protocol>up|down)",
    re.IGNORECASE,
)
_BANDWIDTH = re.compile(r"BW (?P<bw>\d+) Kbit")
_INPUT_RATE = re.compile(r"input rate (?P<in_bps>\d+) bits/sec,\s+(?P<in_pps>\d+) packets/sec")
_OUTPUT_RATE = re.compile(r"output rate (?P<out_bps>\d+) bits/sec,\s+(?P<out_pps>\d+) packets/sec")
_INPUT_ERRORS = re.compile(r"(?P<val>\d+) input errors")
_OUTPUT_ERRORS = re.compile(r"(?P<val>\d+) output errors")
_CRC = re.compile(r"(?P<val>\d+) CRC")
_OUTPUT_DROPS = re.compile(r"Total output drops: (?P<val>\d+)")


def _blank_intf(name: str, line_status: str, protocol: str) -> dict:
    return {
        "name": name,
        "line_status": line_status.lower(),
        "protocol": protocol.lower(),
        "bandwidth_kbps": None,
        "input_bps": 0,
        "input_pps": 0,
        "output_bps": 0,
        "output_pps": 0,
        "input_errors": 0,
        "output_errors": 0,
        "crc_errors": 0,
        "output_drops": 0,
        "utilization_pct": None,
    }


def parse_interfaces(raw: str) -> list:
    interfaces = []
    current = None

    for line in raw.splitlines():
        m = _INTF_HEADER.match(line)
        if m:
            if current:
                interfaces.append(current)
            current = _blank_intf(m.group("name"), m.group("line_status"), m.group("protocol"))
            continue

        if current is None:
            continue

        m = _BANDWIDTH.search(line)
        if m:
            current["bandwidth_kbps"] = int(m.group("bw"))

        m = _INPUT_RATE.search(line)
        if m:
            current["input_bps"] = int(m.group("in_bps"))
            current["input_pps"] = int(m.group("in_pps"))

        m = _OUTPUT_RATE.search(line)
        if m:
            current["output_bps"] = int(m.group("out_bps"))
            current["output_pps"] = int(m.group("out_pps"))

        m = _INPUT_ERRORS.search(line)
        if m:
            current["input_errors"] = int(m.group("val"))

        m = _OUTPUT_ERRORS.search(line)
        if m:
            current["output_errors"] = int(m.group("val"))

        m = _CRC.search(line)
        if m:
            current["crc_errors"] = int(m.group("val"))

        m = _OUTPUT_DROPS.search(line)
        if m:
            current["output_drops"] = int(m.group("val"))

    if current:
        interfaces.append(current)

    for intf in interfaces:
        bw = intf["bandwidth_kbps"]
        if bw and bw > 0:
            peak_bps = max(intf["input_bps"], intf["output_bps"])
            intf["utilization_pct"] = round(peak_bps / (bw * 1000) * 100, 2)

    return interfaces


def collect(args: argparse.Namespace) -> list:
    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }
    log.info("Connecting to %s (%s)", args.host, args.device_type)
    try:
        with ConnectHandler(**device) as conn:
            log.info("Connected — running 'show interfaces'")
            raw = conn.send_command("show interfaces", read_timeout=60)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out: %s", args.host)
        sys.exit(1)

    interfaces = parse_interfaces(raw)
    log.info("Parsed %d interfaces", len(interfaces))

    if args.filter_errors:
        interfaces = [
            i for i in interfaces
            if i["input_errors"] > 0 or i["output_errors"] > 0 or i["crc_errors"] > 0
        ]
        log.info("%d interfaces have error counters > 0", len(interfaces))

    if args.min_utilization is not None:
        interfaces = [
            i for i in interfaces
            if i["utilization_pct"] is not None and i["utilization_pct"] >= args.min_utilization
        ]
        log.info(
            "%d interfaces at or above %.1f%% utilization",
            len(interfaces),
            args.min_utilization,
        )

    return interfaces


def output_json(interfaces: list) -> None:
    print(json.dumps(interfaces, indent=2))


def output_csv(interfaces: list) -> None:
    if not interfaces:
        return
    writer = csv.DictWriter(sys.stdout, fieldnames=list(interfaces[0].keys()))
    writer.writeheader()
    writer.writerows(interfaces)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Parse 'show interfaces' from a Cisco IOS/IOS-XE device into structured data."
    )
    p.add_argument("--host", required=True, help="Device hostname or IP address")
    p.add_argument("--username", required=True, help="SSH username")
    p.add_argument("--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--format",
        dest="fmt",
        choices=["json", "csv"],
        default="json",
        help="Output format (default: json)",
    )
    p.add_argument(
        "--filter-errors",
        action="store_true",
        help="Only output interfaces with non-zero error or CRC counters",
    )
    p.add_argument(
        "--min-utilization",
        type=float,
        default=None,
        metavar="PCT",
        help="Only output interfaces at or above this utilization percentage",
    )
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.password is None:
        args.password = getpass(f"Password for {args.username}@{args.host}: ")

    data = collect(args)

    if not data:
        log.warning("No interfaces matched the specified filters.")
        sys.exit(0)

    if args.fmt == "csv":
        output_csv(data)
    else:
        output_json(data)
```