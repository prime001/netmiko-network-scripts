interface_errors.py - Interface Error Rate Monitor

Purpose:
    Connects to a network device and collects interface error counters
    (input errors, CRC errors, output drops, runts, giants). Flags any
    interface whose error rate exceeds a configurable threshold relative
    to total packets, making it easy to spot degraded links before they
    cause outages.

Usage:
    python interface_errors.py -H 192.168.1.1 -u admin -p secret
    python interface_errors.py -H 192.168.1.1 -u admin --threshold 0.1 --csv errors.csv
    python interface_errors.py -H 192.168.1.1 -u admin --device-type cisco_nxos --all

Prerequisites:
    pip install netmiko
    Tested against: Cisco IOS, IOS-XE, NX-OS
    Requires read-only access (no enable needed for show commands on most platforms).
"""

import argparse
import csv
import getpass
import logging
import re
import sys
from dataclasses import dataclass
from typing import List

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class InterfaceStats:
    name: str
    status: str = "unknown"
    input_packets: int = 0
    input_errors: int = 0
    crc_errors: int = 0
    output_packets: int = 0
    output_drops: int = 0
    runts: int = 0
    giants: int = 0

    @property
    def input_error_rate(self) -> float:
        if self.input_packets == 0:
            return 0.0
        return (self.input_errors / self.input_packets) * 100

    @property
    def output_drop_rate(self) -> float:
        if self.output_packets == 0:
            return 0.0
        return (self.output_drops / self.output_packets) * 100


def parse_interface_counters(output: str) -> List[InterfaceStats]:
    """Parse 'show interfaces' output into InterfaceStats objects."""
    interfaces: List[InterfaceStats] = []
    current: InterfaceStats | None = None

    patterns = {
        "intf":         re.compile(r'^(\S+)\s+is\s+(up|down|administratively down)', re.I),
        "input_packets": re.compile(r'(\d+) packets input', re.I),
        "input_errors":  re.compile(r'(\d+) input errors', re.I),
        "crc_errors":    re.compile(r'(\d+) CRC', re.I),
        "output_packets": re.compile(r'(\d+) packets output', re.I),
        "output_drops":  re.compile(r'(\d+) output drops?', re.I),
        "runts":         re.compile(r'(\d+) runts', re.I),
        "giants":        re.compile(r'(\d+) giants', re.I),
    }

    for line in output.splitlines():
        m = patterns["intf"].match(line)
        if m:
            if current is not None:
                interfaces.append(current)
            current = InterfaceStats(name=m.group(1), status=m.group(2).lower())
            continue

        if current is None:
            continue

        for attr in ("input_packets", "input_errors", "crc_errors",
                     "output_packets", "output_drops", "runts", "giants"):
            hit = patterns[attr].search(line)
            if hit:
                setattr(current, attr, int(hit.group(1)))

    if current is not None:
        interfaces.append(current)

    return interfaces


def collect_errors(
    host: str,
    username: str,
    password: str,
    device_type: str,
    port: int = 22,
    secret: str = "",
) -> List[InterfaceStats]:
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "secret": secret,
        "timeout": 30,
    }
    log.info("Connecting to %s (%s)", host, device_type)
    with ConnectHandler(**device) as conn:
        if secret:
            conn.enable()
        output = conn.send_command("show interfaces", read_timeout=60)
    return parse_interface_counters(output)


def print_report(stats: List[InterfaceStats], threshold: float, show_all: bool) -> None:
    flagged = [
        s for s in stats
        if show_all or s.input_error_rate >= threshold or s.output_drop_rate >= threshold
    ]

    if not flagged:
        print(f"No interfaces exceed the {threshold:.2f}% error threshold.")
        return

    col = f"{'Interface':<32} {'Status':<10} {'InPkts':>10} {'InErr':>8} " \
          f"{'CRC':>6} {'InErr%':>8} {'OutPkts':>10} {'OutDrop':>9} {'OutDrop%':>9}"
    print(col)
    print("-" * len(col))

    for s in sorted(flagged, key=lambda x: x.input_error_rate, reverse=True):
        flag = " *" if (s.input_error_rate >= threshold or s.output_drop_rate >= threshold) else "  "
        print(
            f"{s.name:<32} {s.status:<10} {s.input_packets:>10} {s.input_errors:>8} "
            f"{s.crc_errors:>6} {s.input_error_rate:>7.2f}% {s.output_packets:>10} "
            f"{s.output_drops:>9} {s.output_drop_rate:>8.2f}%{flag}"
        )


def write_csv(stats: List[InterfaceStats], path: str) -> None:
    fields = [
        "interface", "status", "input_packets", "input_errors", "crc_errors",
        "input_error_rate_pct", "output_packets", "output_drops",
        "output_drop_rate_pct", "runts", "giants",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for s in stats:
            writer.writerow({
                "interface": s.name,
                "status": s.status,
                "input_packets": s.input_packets,
                "input_errors": s.input_errors,
                "crc_errors": s.crc_errors,
                "input_error_rate_pct": f"{s.input_error_rate:.4f}",
                "output_packets": s.output_packets,
                "output_drops": s.output_drops,
                "output_drop_rate_pct": f"{s.output_drop_rate:.4f}",
                "runts": s.runts,
                "giants": s.giants,
            })
    log.info("Results written to %s", path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect and report interface error counters from a network device.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--secret", default="", help="Enable secret")
    parser.add_argument("--device-type", default="cisco_ios", help="Netmiko device type")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument(
        "--threshold", type=float, default=0.01,
        help="Error rate %% at which an interface is flagged",
    )
    parser.add_argument(
        "--all", action="store_true", dest="show_all",
        help="Show all interfaces, not only those exceeding threshold",
    )
    parser.add_argument("--csv", metavar="FILE", help="Write full results to CSV")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}@{args.host}: ")

    try:
        stats = collect_errors(
            host=args.host,
            username=args.username,
            password=password,
            device_type=args.device_type,
            port=args.port,
            secret=args.secret,
        )
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        sys.exit(1)
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        sys.exit(1)

    log.info("Parsed %d interfaces", len(stats))
    print_report(stats, threshold=args.threshold, show_all=args.show_all)

    if args.csv:
        write_csv(stats, args.csv)