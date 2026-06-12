```python
"""
interface_health.py - Interface error counter auditor

Purpose:
    Connects to a network device and audits all interfaces for error counters
    (input errors, output errors, CRC, interface resets). Flags any interface
    exceeding a configurable threshold and exits non-zero if issues are found,
    making it suitable for use in monitoring pipelines or cron jobs.

Usage:
    python interface_health.py -d 192.168.1.1 -u admin -p secret
    python interface_health.py -d 10.0.0.1 -u admin -p secret --error-threshold 50
    python interface_health.py -d 10.0.0.1 -u admin -p secret --show-all --output report.txt

Prerequisites:
    pip install netmiko
    Tested against: Cisco IOS, IOS-XE. Other platforms may require parser adjustments.
"""

import argparse
import logging
import re
import sys
from dataclasses import dataclass, field
from typing import List

from netmiko import ConnectHandler
from netmiko.exceptions import NetMikoAuthenticationException, NetMikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


@dataclass
class InterfaceStats:
    name: str
    status: str = "unknown"
    input_errors: int = 0
    output_errors: int = 0
    crc_errors: int = 0
    resets: int = 0
    flagged: bool = False
    reasons: List[str] = field(default_factory=list)


def parse_interfaces(output: str, error_threshold: int) -> List[InterfaceStats]:
    interfaces = []
    blocks = re.split(r'\n(?=\S)', output)

    for block in blocks:
        if not block.strip():
            continue

        header = re.match(
            r'^(\S+)\s+is\s+(up|down|administratively down)',
            block, re.IGNORECASE
        )
        if not header:
            continue

        stats = InterfaceStats(
            name=header.group(1),
            status=header.group(2).lower(),
        )

        m = re.search(r'(\d+)\s+input errors', block)
        if m:
            stats.input_errors = int(m.group(1))

        m = re.search(r'(\d+)\s+CRC', block)
        if m:
            stats.crc_errors = int(m.group(1))

        m = re.search(r'(\d+)\s+output errors', block)
        if m:
            stats.output_errors = int(m.group(1))

        m = re.search(r'(\d+)\s+interface resets', block)
        if m:
            stats.resets = int(m.group(1))

        if stats.input_errors > error_threshold:
            stats.flagged = True
            stats.reasons.append(f"input_errors={stats.input_errors}")
        if stats.output_errors > error_threshold:
            stats.flagged = True
            stats.reasons.append(f"output_errors={stats.output_errors}")
        if stats.crc_errors > error_threshold:
            stats.flagged = True
            stats.reasons.append(f"crc={stats.crc_errors}")
        if stats.resets > 0:
            stats.flagged = True
            stats.reasons.append(f"resets={stats.resets}")

        interfaces.append(stats)

    return interfaces


def format_report(device: str, interfaces: List[InterfaceStats], show_all: bool) -> str:
    lines = [
        f"Interface Error Report — {device}",
        "=" * 60,
    ]

    flagged = [i for i in interfaces if i.flagged]

    if flagged:
        lines.append(f"\n[FLAGGED] {len(flagged)} interface(s) with errors:")
        lines.append(f"  {'Interface':<32} {'Status':<10} Reasons")
        lines.append(f"  {'-'*30} {'-'*8} {'-'*30}")
        for iface in flagged:
            lines.append(
                f"  {iface.name:<32} {iface.status:<10} {', '.join(iface.reasons)}"
            )
    else:
        lines.append("\n[OK] No interfaces exceeded error thresholds.")

    if show_all:
        lines.append(f"\n[ALL INTERFACES]")
        lines.append(
            f"  {'Interface':<32} {'Status':<10} "
            f"{'InErr':>7} {'OutErr':>7} {'CRC':>6} {'Resets':>7}"
        )
        lines.append(f"  {'-'*30} {'-'*8} {'-'*7} {'-'*7} {'-'*6} {'-'*7}")
        for iface in interfaces:
            lines.append(
                f"  {iface.name:<32} {iface.status:<10} "
                f"{iface.input_errors:>7} {iface.output_errors:>7} "
                f"{iface.crc_errors:>6} {iface.resets:>7}"
            )

    clean_count = len(interfaces) - len(flagged)
    lines.append(
        f"\nSummary: {len(flagged)} flagged / {clean_count} clean / {len(interfaces)} total"
    )
    return "\n".join(lines)


def run_check(args: argparse.Namespace) -> int:
    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "timeout": args.timeout,
    }
    if args.enable_secret:
        device_params["secret"] = args.enable_secret

    logger.info("Connecting to %s (%s)", args.device, args.device_type)
    try:
        with ConnectHandler(**device_params) as conn:
            if args.enable_secret:
                conn.enable()
            logger.info("Collecting interface statistics...")
            output = conn.send_command("show interfaces", read_timeout=60)
    except NetMikoAuthenticationException:
        logger.error("Authentication failed for %s", args.device)
        return 1
    except NetMikoTimeoutException:
        logger.error("Connection timed out for %s", args.device)
        return 1
    except Exception as exc:
        logger.error("Unexpected connection error: %s", exc)
        return 1

    interfaces = parse_interfaces(output, args.error_threshold)
    if not interfaces:
        logger.warning("No interfaces parsed — verify device type or output format.")
        return 1

    report = format_report(args.device, interfaces, args.show_all)
    print(report)

    if args.output:
        try:
            with open(args.output, "w") as fh:
                fh.write(report + "\n")
            logger.info("Report written to %s", args.output)
        except OSError as exc:
            logger.error("Could not write report file: %s", exc)

    return 1 if any(i.flagged for i in interfaces) else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit interface error counters on a network device.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument(
        "-t", "--device-type", default="cisco_ios", dest="device_type",
        help="Netmiko device type (cisco_ios, cisco_xe, cisco_nxos, etc.)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument("--timeout", type=int, default=30, help="Connection timeout in seconds")
    parser.add_argument(
        "--enable-secret", dest="enable_secret", default=None,
        help="Enable secret for privilege escalation",
    )
    parser.add_argument(
        "--error-threshold", type=int, default=0, dest="error_threshold",
        help="Flag interfaces with error counters strictly above this value",
    )
    parser.add_argument(
        "--show-all", action="store_true", dest="show_all",
        help="Print all interfaces, not just flagged ones",
    )
    parser.add_argument("--output", default=None, help="Save report to this file")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser


if __name__ == "__main__":
    _parser = build_parser()
    _args = _parser.parse_args()

    if _args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    sys.exit(run_check(_args))
```