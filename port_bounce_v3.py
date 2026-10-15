interface_error_monitor.py - Interface Error and Drop Rate Monitor

Purpose:
    Connects to a Cisco IOS/IOS-XE device and collects per-interface error
    statistics (input errors, CRC, output drops, interface resets). Optionally
    polls twice with a configurable interval and reports per-second delta rates.
    Useful for catching degraded uplinks, faulty transceivers, or duplex
    mismatches before they cause outages.

Usage:
    # Single snapshot — report total counters
    python interface_error_monitor.py -d 192.168.1.1 -u admin

    # Dual-poll — compute error rates over 60-second window
    python interface_error_monitor.py -d 192.168.1.1 -u admin --poll-interval 60

    # Flag interfaces with >5 errors/sec and write all data to CSV
    python interface_error_monitor.py -d 192.168.1.1 -u admin --poll-interval 30 \
        --threshold 5.0 --csv errors.csv

Prerequisites:
    pip install netmiko
"""

import argparse
import csv
import getpass
import logging
import re
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)


@dataclass
class InterfaceStats:
    name: str
    status: str
    input_errors: int = 0
    crc: int = 0
    output_drops: int = 0
    resets: int = 0


def parse_show_interfaces(output: str) -> Dict[str, InterfaceStats]:
    stats: Dict[str, InterfaceStats] = {}
    current: Optional[InterfaceStats] = None

    iface_re = re.compile(r"^(\S+)\s+is\s+(up|down|administratively down)", re.IGNORECASE)
    input_err_re = re.compile(r"(\d+)\s+input errors,\s*(\d+)\s+CRC")
    output_drop_re = re.compile(r"(\d+)\s+output drops")
    reset_re = re.compile(r"(\d+)\s+interface resets")

    for line in output.splitlines():
        m = iface_re.match(line)
        if m:
            current = InterfaceStats(name=m.group(1), status=m.group(2).lower())
            stats[current.name] = current
            continue

        if current is None:
            continue

        m = input_err_re.search(line)
        if m:
            current.input_errors = int(m.group(1))
            current.crc = int(m.group(2))
            continue

        m = output_drop_re.search(line)
        if m:
            current.output_drops = int(m.group(1))
            continue

        m = reset_re.search(line)
        if m:
            current.resets = int(m.group(1))

    return stats


def collect(conn) -> Dict[str, InterfaceStats]:
    return parse_show_interfaces(conn.send_command("show interfaces", read_timeout=60))


def build_results(
    before: Dict[str, InterfaceStats],
    after: Optional[Dict[str, InterfaceStats]],
    elapsed: float,
) -> List[dict]:
    results = []
    source = after if after else before
    for name, s in source.items():
        row: dict = {
            "name": s.name,
            "status": s.status,
            "input_errors_total": s.input_errors,
            "crc_total": s.crc,
            "output_drops_total": s.output_drops,
            "resets_total": s.resets,
            "input_errors_per_sec": 0.0,
            "crc_per_sec": 0.0,
            "output_drops_per_sec": 0.0,
        }
        if after and name in before and elapsed > 0:
            b = before[name]
            row["input_errors_per_sec"] = max(0, s.input_errors - b.input_errors) / elapsed
            row["crc_per_sec"] = max(0, s.crc - b.crc) / elapsed
            row["output_drops_per_sec"] = max(0, s.output_drops - b.output_drops) / elapsed
        results.append(row)
    return results


def report(results: List[dict], threshold: float, csv_path: Optional[str]) -> None:
    flagged = [
        r for r in results
        if r["input_errors_per_sec"] >= threshold
        or r["crc_per_sec"] >= threshold
        or r["output_drops_per_sec"] >= threshold
        or r["input_errors_total"] >= 100
        or r["crc_total"] >= 50
    ]

    if flagged:
        header = (
            f"{'Interface':<30} {'Status':<8} {'InErr/s':>9}"
            f" {'CRC/s':>7} {'Drop/s':>7} {'InErr':>8} {'CRC':>7} {'Drops':>7}"
        )
        print(f"\n{header}")
        print("-" * len(header))
        for r in sorted(flagged, key=lambda x: x["input_errors_per_sec"], reverse=True):
            print(
                f"{r['name']:<30} {r['status']:<8}"
                f" {r['input_errors_per_sec']:>9.2f}"
                f" {r['crc_per_sec']:>7.2f}"
                f" {r['output_drops_per_sec']:>7.2f}"
                f" {r['input_errors_total']:>8}"
                f" {r['crc_total']:>7}"
                f" {r['output_drops_total']:>7}"
            )
        print(f"\n{len(flagged)} interface(s) flagged.")
    else:
        print("\nNo interfaces exceeded error thresholds.")

    if csv_path and results:
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
            writer.writeheader()
            writer.writerows(results)
        log.info("Full stats written to %s", csv_path)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Monitor interface error counters on Cisco IOS/IOS-XE devices."
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    p.add_argument("--device-type", default="cisco_ios", help="Netmiko device type")
    p.add_argument("--port", type=int, default=22)
    p.add_argument(
        "--poll-interval",
        type=int,
        default=0,
        metavar="SECONDS",
        help="Seconds between two polls for rate calculation (0 = single snapshot)",
    )
    p.add_argument(
        "--threshold",
        type=float,
        default=1.0,
        help="Errors/sec that flags an interface (default: 1.0)",
    )
    p.add_argument("--csv", metavar="FILE", help="Write all interface stats to a CSV file")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main() -> None:
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}@{args.device}: ")

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": password,
        "port": args.port,
    }

    try:
        log.info("Connecting to %s", args.device)
        with ConnectHandler(**device_params) as conn:
            log.info("Collecting interface stats (poll 1)")
            before = collect(conn)

            after: Optional[Dict[str, InterfaceStats]] = None
            elapsed = 0.0

            if args.poll_interval > 0:
                log.info("Waiting %d seconds before second poll...", args.poll_interval)
                time.sleep(args.poll_interval)
                log.info("Collecting interface stats (poll 2)")
                after = collect(conn)
                elapsed = float(args.poll_interval)

        results = build_results(before, after, elapsed)
        log.info("Parsed %d interfaces", len(results))
        report(results, args.threshold, args.csv)

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.device)
        sys.exit(1)
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()