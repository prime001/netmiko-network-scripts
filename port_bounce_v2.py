interface_errors.py - Interface Error Counter Monitor

Purpose:
    Connects to a network device via SSH and collects interface error statistics
    (input errors, output errors, CRC, drops). Flags interfaces whose counters
    exceed configurable thresholds. Useful for NOC triage, pre/post-maintenance
    baseline checks, and catching degraded links before they cause outages.

Usage:
    python interface_errors.py -H 192.168.1.1 -u admin -p secret
    python interface_errors.py -H 10.0.0.1 -u admin -p secret \
        --device-type cisco_nxos --crc-threshold 5 --error-threshold 50
    python interface_errors.py -H 10.0.0.1 -u admin -p secret --all --json

Prerequisites:
    pip install netmiko
    Supported device types: cisco_ios, cisco_nxos, cisco_xr, juniper_junos

Exit codes:
    0 — connected successfully, no interfaces exceeded thresholds
    1 — connection or auth failure
    2 — one or more interfaces exceeded thresholds (useful for scripting)
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass
from typing import List

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)


@dataclass
class InterfaceStats:
    name: str
    status: str = "unknown"
    input_errors: int = 0
    output_errors: int = 0
    crc: int = 0
    input_drops: int = 0
    output_drops: int = 0


def _parse_cisco(output: str) -> List[InterfaceStats]:
    interfaces: List[InterfaceStats] = []
    current = None

    for line in output.splitlines():
        m = re.match(r'^(\S+) is (\S.*)', line)
        if m:
            if current:
                interfaces.append(current)
            current = InterfaceStats(name=m.group(1), status=m.group(2).rstrip(','))
            continue

        if current is None:
            continue

        m = re.search(r'(\d+) input errors', line)
        if m:
            current.input_errors = int(m.group(1))
        m = re.search(r'(\d+) CRC', line)
        if m:
            current.crc = int(m.group(1))
        m = re.search(r'(\d+) output errors', line)
        if m:
            current.output_errors = int(m.group(1))
        m = re.search(r'(\d+) input drops', line)
        if m:
            current.input_drops = int(m.group(1))
        m = re.search(r'(\d+) output drops', line)
        if m:
            current.output_drops = int(m.group(1))
        m = re.search(r'(\d+) no buffer', line)
        if m:
            current.input_drops += int(m.group(1))

    if current:
        interfaces.append(current)
    return interfaces


def _parse_juniper(output: str) -> List[InterfaceStats]:
    interfaces: List[InterfaceStats] = []
    current = None

    for line in output.splitlines():
        m = re.match(r'^Physical interface:\s+(\S+)', line)
        if m:
            if current:
                interfaces.append(current)
            current = InterfaceStats(name=m.group(1))
            continue

        if current is None:
            continue

        m = re.search(r'Input errors:\s+(\d+)', line)
        if m:
            current.input_errors = int(m.group(1))
        m = re.search(r'Output errors:\s+(\d+)', line)
        if m:
            current.output_errors = int(m.group(1))
        m = re.search(r'Frame-check-sequence errors:\s+(\d+)', line)
        if m:
            current.crc = int(m.group(1))
        m = re.search(r'Input drops:\s+(\d+)', line)
        if m:
            current.input_drops = int(m.group(1))
        m = re.search(r'Output drops:\s+(\d+)', line)
        if m:
            current.output_drops = int(m.group(1))

    if current:
        interfaces.append(current)
    return interfaces


def collect_stats(conn, device_type: str) -> List[InterfaceStats]:
    if "juniper" in device_type:
        output = conn.send_command("show interfaces extensive", read_timeout=90)
        return _parse_juniper(output)
    output = conn.send_command("show interfaces", read_timeout=60)
    return _parse_cisco(output)


def apply_thresholds(
    stats: List[InterfaceStats],
    error_threshold: int,
    crc_threshold: int,
    drop_threshold: int,
) -> List[InterfaceStats]:
    return [
        s for s in stats
        if (
            s.input_errors > error_threshold
            or s.output_errors > error_threshold
            or s.crc > crc_threshold
            or (s.input_drops + s.output_drops) > drop_threshold
        )
    ]


def print_table(host: str, flagged: List[InterfaceStats], total: int) -> None:
    print(f"\n{'='*70}")
    print(f"Interface Error Report  |  {host}")
    print(f"Interfaces checked: {total}  |  Flagged: {len(flagged)}")
    print(f"{'='*70}")
    if not flagged:
        print("No interfaces exceeded thresholds.\n")
        return
    header = f"{'Interface':<32} {'In Err':>8} {'Out Err':>8} {'CRC':>8} {'Drops':>8}"
    print(header)
    print("-" * 70)
    for s in flagged:
        drops = s.input_drops + s.output_drops
        print(f"{s.name[:32]:<32} {s.input_errors:>8} {s.output_errors:>8} {s.crc:>8} {drops:>8}")
    print()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Report interface error counters via netmiko.")
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("--secret", default="", help="Enable secret for privileged mode")
    p.add_argument(
        "--device-type", default="cisco_ios",
        choices=["cisco_ios", "cisco_nxos", "cisco_xr", "juniper_junos"],
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--error-threshold", type=int, default=0,
        help="Flag when input/output errors exceed N (default: 0)",
    )
    p.add_argument(
        "--crc-threshold", type=int, default=0,
        help="Flag when CRC errors exceed N (default: 0)",
    )
    p.add_argument(
        "--drop-threshold", type=int, default=0,
        help="Flag when total drops exceed N (default: 0)",
    )
    p.add_argument("--all", action="store_true", help="Show all interfaces, not just flagged")
    p.add_argument("--json", action="store_true", help="Output results as JSON")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return p


def main() -> int:
    args = build_parser().parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "secret": args.secret,
    }

    log.info("Connecting to %s (%s)", args.host, args.device_type)
    try:
        with ConnectHandler(**device) as conn:
            if args.secret:
                conn.enable()
            stats = collect_stats(conn, args.device_type)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.host)
        return 1
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        return 1
    except Exception as exc:
        log.error("Unexpected error connecting to %s: %s", args.host, exc)
        return 1

    log.info("Collected stats for %d interfaces", len(stats))

    if args.all:
        display = stats
    else:
        display = apply_thresholds(
            stats,
            error_threshold=args.error_threshold,
            crc_threshold=args.crc_threshold,
            drop_threshold=args.drop_threshold,
        )

    if args.json:
        print(json.dumps({
            "host": args.host,
            "total_interfaces": len(stats),
            "flagged_count": len(display),
            "interfaces": [
                {
                    "name": s.name,
                    "status": s.status,
                    "input_errors": s.input_errors,
                    "output_errors": s.output_errors,
                    "crc": s.crc,
                    "input_drops": s.input_drops,
                    "output_drops": s.output_drops,
                }
                for s in display
            ],
        }, indent=2))
    else:
        print_table(args.host, display, len(stats))

    return 2 if display and not args.all else 0


if __name__ == "__main__":
    sys.exit(main())