```python
"""
interface_errors.py - Interface Error Rate Monitor

Purpose:
    Connects to a Cisco IOS/IOS-XE/NX-OS device and reports interfaces
    with error counters (CRC, input errors, output drops, runts, giants)
    exceeding configurable thresholds. With --interval, polls twice and
    reports delta counts so you can distinguish new errors from historical
    accumulation.

Usage:
    python interface_errors.py -H 192.168.1.1 -u admin -p secret
    python interface_errors.py -H 192.168.1.1 -u admin -p secret \\
        --interval 60 --crc-threshold 0 --drop-threshold 50
    python interface_errors.py -H 192.168.1.1 -u admin -p secret \\
        --device-type cisco_nxos --all

Prerequisites:
    pip install netmiko
    Device must support 'show interfaces' (Cisco IOS / IOS-XE / NX-OS).
    Exit code 0 = clean, 1 = thresholds exceeded, 2 = connection error.
"""

import argparse
import logging
import re
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(format="%(asctime)s [%(levelname)s] %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)


@dataclass
class InterfaceCounters:
    name: str
    input_errors: int = 0
    crc: int = 0
    output_drops: int = 0
    runts: int = 0
    giants: int = 0
    collisions: int = 0


_IFACE_RE = re.compile(r"^(\S+)\s+is\s+(?:up|down|administratively down)", re.IGNORECASE)
_INPUT_ERR_RE = re.compile(r"(\d+)\s+input errors")
_CRC_RE = re.compile(r"(\d+)\s+CRC")
_DROP_RE = re.compile(r"(\d+)\s+(?:output\s+)?drops")
_RUNTS_RE = re.compile(r"(\d+)\s+runts")
_GIANTS_RE = re.compile(r"(\d+)\s+giants")
_COLLISIONS_RE = re.compile(r"(\d+)\s+collisions")


def parse_counters(output: str) -> Dict[str, InterfaceCounters]:
    counters: Dict[str, InterfaceCounters] = {}
    current: Optional[str] = None

    for line in output.splitlines():
        m = _IFACE_RE.match(line)
        if m:
            current = m.group(1)
            counters[current] = InterfaceCounters(name=current)
            continue

        if current is None:
            continue

        c = counters[current]
        if m := _INPUT_ERR_RE.search(line):
            c.input_errors = int(m.group(1))
        if m := _CRC_RE.search(line):
            c.crc = int(m.group(1))
        if m := _DROP_RE.search(line):
            c.output_drops = int(m.group(1))
        if m := _RUNTS_RE.search(line):
            c.runts = int(m.group(1))
        if m := _GIANTS_RE.search(line):
            c.giants = int(m.group(1))
        if m := _COLLISIONS_RE.search(line):
            c.collisions = int(m.group(1))

    return counters


def compute_delta(
    before: Dict[str, InterfaceCounters],
    after: Dict[str, InterfaceCounters],
) -> Dict[str, InterfaceCounters]:
    result: Dict[str, InterfaceCounters] = {}
    for name, a in after.items():
        b = before.get(name, InterfaceCounters(name=name))
        d = InterfaceCounters(name=name)
        d.input_errors = max(0, a.input_errors - b.input_errors)
        d.crc = max(0, a.crc - b.crc)
        d.output_drops = max(0, a.output_drops - b.output_drops)
        d.runts = max(0, a.runts - b.runts)
        d.giants = max(0, a.giants - b.giants)
        d.collisions = max(0, a.collisions - b.collisions)
        result[name] = d
    return result


def print_report(
    counters: Dict[str, InterfaceCounters],
    crc_threshold: int,
    input_err_threshold: int,
    drop_threshold: int,
    show_all: bool,
    is_delta: bool,
) -> int:
    def exceeds(c: InterfaceCounters) -> bool:
        return c.crc >= crc_threshold or c.input_errors >= input_err_threshold or c.output_drops >= drop_threshold

    rows: List[InterfaceCounters] = [
        c for c in counters.values() if exceeds(c) or show_all
    ]
    rows.sort(key=lambda c: c.crc + c.input_errors + c.output_drops, reverse=True)

    label = "delta (new errors only)" if is_delta else "cumulative"
    if not rows:
        log.info("No interfaces exceeded thresholds [%s]", label)
        return 0

    hdr = f"{'Interface':<26} {'InErrs':>8} {'CRC':>8} {'Drops':>8} {'Runts':>7} {'Giants':>7} {'Collisions':>11}"
    print(f"\n  Counters [{label}]")
    print(f"  {hdr}")
    print(f"  {'-' * len(hdr)}")
    flagged = 0
    for c in rows:
        flag = "! " if exceeds(c) else "  "
        print(
            f"  {flag}{c.name:<24} {c.input_errors:>8} {c.crc:>8} "
            f"{c.output_drops:>8} {c.runts:>7} {c.giants:>7} {c.collisions:>11}"
        )
        if exceeds(c):
            flagged += 1
    print()
    return flagged


def main(args: argparse.Namespace) -> int:
    device_params = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "secret": args.enable_secret or args.password,
        "port": args.port,
    }

    try:
        log.info("Connecting to %s (%s)", args.host, args.device_type)
        with ConnectHandler(**device_params) as conn:
            if args.enable_secret:
                conn.enable()

            log.info("Snapshot 1 — collecting interface counters")
            snap1 = parse_counters(conn.send_command("show interfaces", read_timeout=60))
            log.info("  %d interfaces parsed", len(snap1))

            if args.interval:
                log.info("Waiting %ds before second snapshot...", args.interval)
                time.sleep(args.interval)
                log.info("Snapshot 2 — collecting interface counters")
                snap2 = parse_counters(conn.send_command("show interfaces", read_timeout=60))
                counters = compute_delta(snap1, snap2)
                is_delta = True
            else:
                counters = snap1
                is_delta = False

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 2
    except NetmikoTimeoutException:
        log.error("Timed out connecting to %s", args.host)
        return 2
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        return 2

    flagged = print_report(
        counters,
        crc_threshold=args.crc_threshold,
        input_err_threshold=args.input_err_threshold,
        drop_threshold=args.drop_threshold,
        show_all=args.all,
        is_delta=is_delta,
    )

    if flagged:
        log.warning("%d interface(s) on %s exceeded error thresholds", flagged, args.host)
        return 1
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Report interface error counters exceeding configurable thresholds.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    conn_grp = parser.add_argument_group("connection")
    conn_grp.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    conn_grp.add_argument("-u", "--username", required=True, help="SSH username")
    conn_grp.add_argument("-p", "--password", required=True, help="SSH password")
    conn_grp.add_argument("-e", "--enable-secret", help="Enable secret (if required)")
    conn_grp.add_argument("--device-type", default="cisco_ios", help="Netmiko device type")
    conn_grp.add_argument("--port", type=int, default=22, help="SSH port")

    thresh_grp = parser.add_argument_group("thresholds")
    thresh_grp.add_argument("--crc-threshold", type=int, default=1, metavar="N",
                            help="Flag interfaces with >= N CRC errors")
    thresh_grp.add_argument("--input-err-threshold", type=int, default=10, metavar="N",
                            help="Flag interfaces with >= N input errors")
    thresh_grp.add_argument("--drop-threshold", type=int, default=10, metavar="N",
                            help="Flag interfaces with >= N output drops")

    parser.add_argument("--interval", type=int, default=0, metavar="SECS",
                        help="Poll twice SECS apart and report delta counts (0 = single snapshot)")
    parser.add_argument("--all", action="store_true",
                        help="Show all interfaces, not just those exceeding thresholds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    parsed = parser.parse_args()
    if parsed.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    sys.exit(main(parsed))
```