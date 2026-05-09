```python
"""
interface_stats.py - Interface Error Counter Monitor

Purpose:
    Polls interface error counters (CRC, input errors, output drops, interface
    resets) from Cisco IOS/IOS-XE/NX-OS devices and reports interfaces that
    exceed configured thresholds. Useful for identifying degraded physical links
    before they cause outages or SLA violations.

Usage:
    # Flag interfaces with any CRC errors
    python interface_stats.py --host 10.0.0.1 -u admin -p secret

    # Custom thresholds
    python interface_stats.py --host 10.0.0.1 -u admin -p secret \
        --threshold-crc 5 --threshold-drops 50

    # Report all interfaces as JSON (useful for piping to monitoring systems)
    python interface_stats.py --host 10.0.0.1 -u admin -p secret --all --json

Prerequisites:
    pip install netmiko
    Device must support 'show interfaces' (tested on IOS 15.x, IOS-XE 17.x, NX-OS 9.x)
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass, field

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


@dataclass
class InterfaceStats:
    name: str
    status: str = "unknown"
    crc_errors: int = 0
    input_errors: int = 0
    output_drops: int = 0
    resets: int = 0
    violations: list = field(default_factory=list)


def parse_show_interfaces(output: str) -> list:
    interfaces = []
    current = None

    intf_re = re.compile(r"^(\S+) is (up|down|administratively down)")
    crc_re = re.compile(r"(\d+) CRC")
    input_err_re = re.compile(r"(\d+) input errors")
    output_drop_re = re.compile(r"(\d+) output drops")
    reset_re = re.compile(r"(\d+) resets")

    for line in output.splitlines():
        m = intf_re.match(line)
        if m:
            if current:
                interfaces.append(current)
            current = InterfaceStats(name=m.group(1), status=m.group(2))
            continue

        if current is None:
            continue

        for pattern, attr in [
            (crc_re, "crc_errors"),
            (input_err_re, "input_errors"),
            (output_drop_re, "output_drops"),
            (reset_re, "resets"),
        ]:
            m = pattern.search(line)
            if m:
                setattr(current, attr, int(m.group(1)))

    if current:
        interfaces.append(current)

    return interfaces


def check_thresholds(stats: list, thresholds: dict) -> list:
    flagged = []
    for intf in stats:
        violations = []
        checks = [
            ("crc_errors", "crc", "CRC"),
            ("input_errors", "input_errors", "input_errors"),
            ("output_drops", "output_drops", "output_drops"),
            ("resets", "resets", "resets"),
        ]
        for attr, key, label in checks:
            value = getattr(intf, attr)
            limit = thresholds[key]
            if value >= limit:
                violations.append(f"{label}={value} (threshold={limit})")
        if violations:
            intf.violations = violations
            flagged.append(intf)
    return flagged


def collect_stats(args: argparse.Namespace):
    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "timeout": 30,
    }
    if args.enable_password:
        device["secret"] = args.enable_password

    try:
        logger.info("Connecting to %s", args.host)
        with ConnectHandler(**device) as conn:
            if args.enable_password:
                conn.enable()
            output = conn.send_command("show interfaces")
        logger.info("Disconnected from %s", args.host)
    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s", args.host)
        return None
    except NetmikoTimeoutException:
        logger.error("Connection timed out for %s", args.host)
        return None
    except Exception as exc:
        logger.error("Unexpected error for %s: %s", args.host, exc)
        return None

    return parse_show_interfaces(output)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Monitor interface error counters on Cisco devices",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("--username", "-u", required=True, help="SSH username")
    p.add_argument("--password", "-p", required=True, help="SSH password")
    p.add_argument("--enable-password", "-e", default="", help="Enable password")
    p.add_argument("--port", type=int, default=22)
    p.add_argument(
        "--device-type", default="cisco_ios",
        choices=["cisco_ios", "cisco_xe", "cisco_nxos"],
    )
    p.add_argument("--threshold-crc", type=int, default=1, metavar="N",
                   help="Flag interfaces with CRC errors >= N")
    p.add_argument("--threshold-input-errors", type=int, default=1, metavar="N",
                   help="Flag interfaces with input errors >= N")
    p.add_argument("--threshold-output-drops", type=int, default=1, metavar="N",
                   help="Flag interfaces with output drops >= N")
    p.add_argument("--threshold-resets", type=int, default=1, metavar="N",
                   help="Flag interfaces with resets >= N")
    p.add_argument("--all", action="store_true",
                   help="Report all interfaces, not just violations")
    p.add_argument("--json", action="store_true", dest="json_output",
                   help="Output results as JSON")
    return p


def main() -> int:
    args = build_parser().parse_args()

    thresholds = {
        "crc": args.threshold_crc,
        "input_errors": args.threshold_input_errors,
        "output_drops": args.threshold_output_drops,
        "resets": args.threshold_resets,
    }

    stats = collect_stats(args)
    if stats is None:
        return 1

    flagged = check_thresholds(stats, thresholds)
    report_set = stats if args.all else flagged

    if args.json_output:
        data = {
            "host": args.host,
            "total_interfaces": len(stats),
            "violation_count": len(flagged),
            "interfaces": [
                {
                    "name": s.name,
                    "status": s.status,
                    "crc_errors": s.crc_errors,
                    "input_errors": s.input_errors,
                    "output_drops": s.output_drops,
                    "resets": s.resets,
                    "violations": s.violations,
                }
                for s in report_set
            ],
        }
        print(json.dumps(data, indent=2))
    else:
        print(f"\nInterface Error Report — {args.host}")
        print(f"Total interfaces: {len(stats)}   Violations: {len(flagged)}\n")
        if not report_set:
            print("No violations found.")
        for s in report_set:
            flag = " [VIOLATION]" if s.violations else ""
            print(f"  {s.name} ({s.status}){flag}")
            print(f"    CRC={s.crc_errors}  input_errors={s.input_errors}  "
                  f"output_drops={s.output_drops}  resets={s.resets}")
            for v in s.violations:
                print(f"    ! {v}")

    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
```