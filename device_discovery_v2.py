```python
"""
interface_error_monitor.py - Monitor interface error counters on network devices.

Purpose:
    Connects to a network device via SSH, collects interface error statistics,
    and reports interfaces with errors above configurable thresholds. Supports
    delta mode: collects two snapshots separated by a configurable interval so
    you see the error *rate* rather than cumulative lifetime counts -- far more
    useful when chasing an active fault.

Usage:
    # Cumulative errors, report all interfaces:
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret

    # Rate mode: compare snapshots 60 seconds apart:
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret --delta --interval 60

    # Flag interfaces with >= 100 total errors, save to CSV:
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret --threshold 100 --output errors.csv

Prerequisites:
    pip install netmiko
    Device must support: show interfaces  (Cisco IOS / IOS-XE / NX-OS)
    SSH access with privilege level sufficient to run show commands.

Exit codes:
    0 - success, no interfaces above threshold
    1 - connection / auth failure
    2 - success, one or more interfaces flagged above threshold
"""

import argparse
import csv
import logging
import re
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)


@dataclass
class InterfaceErrors:
    name: str
    input_errors: int = 0
    crc: int = 0
    output_errors: int = 0
    input_drops: int = 0
    output_drops: int = 0
    resets: int = 0

    def total(self) -> int:
        return self.input_errors + self.output_errors + self.input_drops + self.output_drops

    def delta(self, previous: "InterfaceErrors") -> "InterfaceErrors":
        return InterfaceErrors(
            name=self.name,
            input_errors=max(0, self.input_errors - previous.input_errors),
            crc=max(0, self.crc - previous.crc),
            output_errors=max(0, self.output_errors - previous.output_errors),
            input_drops=max(0, self.input_drops - previous.input_drops),
            output_drops=max(0, self.output_drops - previous.output_drops),
            resets=max(0, self.resets - previous.resets),
        )


def parse_interfaces(raw: str) -> Dict[str, InterfaceErrors]:
    """Parse 'show interfaces' output into per-interface error counters."""
    interfaces: Dict[str, InterfaceErrors] = {}
    current: Optional[str] = None

    for line in raw.splitlines():
        m = re.match(r'^(\S+)\s+is\s+(?:up|down|administratively down)', line)
        if m:
            current = m.group(1)
            interfaces[current] = InterfaceErrors(name=current)
            continue

        if current is None:
            continue

        obj = interfaces[current]

        m = re.search(r'(\d+)\s+input errors.*?(\d+)\s+CRC', line)
        if m:
            obj.input_errors = int(m.group(1))
            obj.crc = int(m.group(2))

        m = re.search(r'(\d+)\s+output errors.*?(\d+)\s+interface resets', line)
        if m:
            obj.output_errors = int(m.group(1))
            obj.resets = int(m.group(2))

        m = re.search(r'(\d+)\s+input\s+drops', line)
        if m:
            obj.input_drops = int(m.group(1))

        m = re.search(r'(\d+)\s+output\s+drops', line)
        if m:
            obj.output_drops = int(m.group(1))

    return interfaces


def collect(conn) -> Dict[str, InterfaceErrors]:
    log.info("Collecting interface statistics...")
    return parse_interfaces(conn.send_command("show interfaces", read_timeout=60))


def print_report(
    errors: Dict[str, InterfaceErrors],
    threshold: int,
    interval: Optional[int],
) -> List[InterfaceErrors]:
    label = f" / {interval}s" if interval else " cumulative"
    flagged = sorted(
        [e for e in errors.values() if e.total() >= threshold],
        key=lambda e: e.total(),
        reverse=True,
    )

    if not flagged:
        log.info("No interfaces exceed threshold of %d%s", threshold, label)
        return flagged

    print(
        f"\n{'Interface':<32} {'In-Err':>8} {'CRC':>8} "
        f"{'Out-Err':>8} {'In-Drop':>8} {'Out-Drop':>8} {'Resets':>8}"
    )
    print("-" * 88)
    for e in flagged:
        print(
            f"{e.name:<32} {e.input_errors:>8} {e.crc:>8} {e.output_errors:>8}"
            f" {e.input_drops:>8} {e.output_drops:>8} {e.resets:>8}"
        )
    print(f"\n{len(flagged)} interface(s) above threshold of {threshold}{label}")
    return flagged


def write_csv(flagged: List[InterfaceErrors], path: str) -> None:
    fields = [
        "interface", "input_errors", "crc", "output_errors",
        "input_drops", "output_drops", "resets",
    ]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for e in flagged:
            w.writerow({
                "interface": e.name,
                "input_errors": e.input_errors,
                "crc": e.crc,
                "output_errors": e.output_errors,
                "input_drops": e.input_drops,
                "output_drops": e.output_drops,
                "resets": e.resets,
            })
    log.info("Results written to %s", path)


def build_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Monitor interface error counters on network devices."
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--threshold", type=int, default=0,
        help="Minimum total errors to flag an interface (default: 0 = report all)",
    )
    p.add_argument(
        "--delta", action="store_true",
        help="Collect two snapshots and report error rate over the interval",
    )
    p.add_argument(
        "--interval", type=int, default=60,
        help="Seconds between snapshots in delta mode (default: 60)",
    )
    p.add_argument("--output", metavar="FILE", help="Write flagged interfaces to a CSV file")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p.parse_args()


def main() -> int:
    args = build_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }

    try:
        log.info("Connecting to %s...", args.device)
        with ConnectHandler(**params) as conn:
            snap1 = collect(conn)

            if args.delta:
                log.info("Waiting %d seconds for second snapshot...", args.interval)
                time.sleep(args.interval)
                snap2 = collect(conn)
                errors = {
                    name: snap2[name].delta(snap1[name])
                    for name in snap2
                    if name in snap1
                }
                flagged = print_report(errors, args.threshold, args.interval)
            else:
                flagged = print_report(snap1, args.threshold, None)

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        return 1
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.device)
        return 1
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        return 1

    if args.output and flagged:
        write_csv(flagged, args.output)

    return 2 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
```