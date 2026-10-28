interface_error_monitor.py - Interface error counter threshold monitor

Connects to a network device, parses 'show interfaces' output, and reports
any interfaces whose error counters exceed configurable thresholds. Useful
for proactive fault detection before errors cause outages.

Usage:
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret \
        --input-errors 100 --crc-errors 50 --output-drops 200 \
        --device-type cisco_ios --csv errors.csv

Prerequisites:
    pip install netmiko
    Tested with: Cisco IOS, IOS-XE (adjust regex for other vendors)
"""

import argparse
import csv
import logging
import re
import sys
from dataclasses import dataclass, fields
from typing import Optional

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class InterfaceErrors:
    name: str
    status: str
    input_errors: int
    crc_errors: int
    output_drops: int
    input_drops: int
    resets: int


_IFACE_BLOCK_RE = re.compile(
    r"^(\S+) is (\S+.*?), line protocol",
    re.MULTILINE,
)
_INPUT_ERRORS_RE = re.compile(r"(\d+) input errors")
_CRC_RE = re.compile(r"(\d+) CRC")
_OUTPUT_DROPS_RE = re.compile(r"(\d+) output drops")
_INPUT_DROPS_RE = re.compile(r"(\d+) input drops")
_RESETS_RE = re.compile(r"(\d+) interface resets")


def _extract(pattern: re.Pattern, text: str, default: int = 0) -> int:
    m = pattern.search(text)
    return int(m.group(1)) if m else default


def parse_interfaces(raw: str) -> list[InterfaceErrors]:
    results = []
    blocks = re.split(r"(?=^\S+ is (?:up|down|admin))", raw, flags=re.MULTILINE)
    for block in blocks:
        m = _IFACE_BLOCK_RE.match(block.strip())
        if not m:
            continue
        results.append(InterfaceErrors(
            name=m.group(1),
            status=m.group(2),
            input_errors=_extract(_INPUT_ERRORS_RE, block),
            crc_errors=_extract(_CRC_RE, block),
            output_drops=_extract(_OUTPUT_DROPS_RE, block),
            input_drops=_extract(_INPUT_DROPS_RE, block),
            resets=_extract(_RESETS_RE, block),
        ))
    return results


def check_thresholds(
    ifaces: list[InterfaceErrors],
    input_errors: int,
    crc_errors: int,
    output_drops: int,
) -> list[InterfaceErrors]:
    return [
        i for i in ifaces
        if i.input_errors >= input_errors
        or i.crc_errors >= crc_errors
        or i.output_drops >= output_drops
    ]


def write_csv(path: str, ifaces: list[InterfaceErrors]) -> None:
    field_names = [f.name for f in fields(InterfaceErrors)]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=field_names)
        writer.writeheader()
        for iface in ifaces:
            writer.writerow({f.name: getattr(iface, f.name) for f in fields(iface)})
    log.info("Results written to %s", path)


def run(args: argparse.Namespace) -> int:
    device = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }

    log.info("Connecting to %s (%s)", args.device, args.device_type)
    try:
        with ConnectHandler(**device) as conn:
            log.info("Connected. Fetching interface counters...")
            raw = conn.send_command("show interfaces", read_timeout=60)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.device)
        return 1
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.device)
        return 1

    all_ifaces = parse_interfaces(raw)
    log.info("Parsed %d interfaces", len(all_ifaces))

    flagged = check_thresholds(
        all_ifaces,
        input_errors=args.input_errors,
        crc_errors=args.crc_errors,
        output_drops=args.output_drops,
    )

    if not flagged:
        log.info("All interfaces within thresholds.")
    else:
        print(f"\n{'Interface':<30} {'Status':<20} {'InErr':>8} {'CRC':>8} {'OutDrop':>8} {'InDrop':>8} {'Resets':>8}")
        print("-" * 92)
        for i in flagged:
            print(f"{i.name:<30} {i.status:<20} {i.input_errors:>8} {i.crc_errors:>8} "
                  f"{i.output_drops:>8} {i.input_drops:>8} {i.resets:>8}")
        print(f"\n{len(flagged)} interface(s) exceeded thresholds.")

    if args.csv:
        write_csv(args.csv, flagged if args.csv_flagged_only else all_ifaces)

    return 1 if flagged else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Monitor interface error counters against thresholds.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("--port", type=int, default=22, help="SSH port")
    p.add_argument("--device-type", default="cisco_ios", help="Netmiko device type")
    p.add_argument("--input-errors", type=int, default=0, metavar="N",
                   help="Alert if input errors >= N")
    p.add_argument("--crc-errors", type=int, default=0, metavar="N",
                   help="Alert if CRC errors >= N")
    p.add_argument("--output-drops", type=int, default=0, metavar="N",
                   help="Alert if output drops >= N")
    p.add_argument("--csv", metavar="FILE", help="Write results to CSV file")
    p.add_argument("--csv-flagged-only", action="store_true",
                   help="Write only flagged interfaces to CSV (default: all)")
    return p


if __name__ == "__main__":
    sys.exit(run(build_parser().parse_args()))