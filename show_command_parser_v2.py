```python
"""
Interface Error Rate Reporter

Connects to a Cisco IOS/IOS-XE device, collects counters from
'show interfaces', and flags any interfaces with input/output error
rates or CRC counts above a configurable threshold.

Usage:
    python interface_error_report.py -d 192.168.1.1 -u admin -p secret
    python interface_error_report.py -d 10.0.0.1 -u admin -p secret \\
        --threshold 0.005 --output report.txt --device-type cisco_ios

Prerequisites:
    pip install netmiko
"""

import argparse
import logging
import re
import sys
from dataclasses import dataclass
from typing import List, Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetMikoAuthenticationException, NetMikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class InterfaceCounters:
    name: str
    input_packets: int = 0
    output_packets: int = 0
    input_errors: int = 0
    output_errors: int = 0
    crc_errors: int = 0
    output_drops: int = 0
    resets: int = 0

    @property
    def input_error_rate(self) -> float:
        return self.input_errors / self.input_packets if self.input_packets else 0.0

    @property
    def output_error_rate(self) -> float:
        return self.output_errors / self.output_packets if self.output_packets else 0.0

    @property
    def total_errors(self) -> int:
        return self.input_errors + self.output_errors + self.crc_errors


def parse_show_interfaces(output: str) -> List[InterfaceCounters]:
    interfaces: List[InterfaceCounters] = []

    # Each interface block starts at the beginning of a non-whitespace line
    blocks = re.split(r"\n(?=\S)", output)

    for block in blocks:
        name_match = re.match(
            r"^(\S+)\s+is\s+(?:up|down|administratively down)", block
        )
        if not name_match:
            continue

        iface = InterfaceCounters(name=name_match.group(1))

        patterns = [
            ("input_packets", r"(\d+) packets input"),
            ("output_packets", r"(\d+) packets output"),
            ("input_errors", r"(\d+) input errors"),
            ("output_errors", r"(\d+) output errors"),
            ("crc_errors", r"(\d+) CRC"),
            ("output_drops", r"(\d+) output drops"),
            ("resets", r"(\d+) interface resets"),
        ]

        for attr, pattern in patterns:
            m = re.search(pattern, block)
            if m:
                setattr(iface, attr, int(m.group(1)))

        interfaces.append(iface)

    return interfaces


def generate_report(
    host: str, interfaces: List[InterfaceCounters], threshold: float
) -> str:
    flagged = [
        iface
        for iface in interfaces
        if iface.input_error_rate > threshold
        or iface.output_error_rate > threshold
        or iface.crc_errors > 0
        or iface.resets > 10
    ]

    lines = [
        f"Interface Error Report — {host}",
        "=" * 68,
        f"Error rate threshold : {threshold:.2%}",
        f"Interfaces scanned   : {len(interfaces)}",
        f"Interfaces flagged   : {len(flagged)}",
        "",
    ]

    if not flagged:
        lines.append("All interfaces are within acceptable error thresholds.")
        return "\n".join(lines)

    col = f"{'Interface':<28} {'In Err':>9} {'Out Err':>9} {'CRC':>7} {'Resets':>7} {'In Rate':>9} {'Out Rate':>9}"
    lines.append(col)
    lines.append("-" * len(col))

    for iface in sorted(flagged, key=lambda x: x.total_errors, reverse=True):
        lines.append(
            f"{iface.name:<28} "
            f"{iface.input_errors:>9,} "
            f"{iface.output_errors:>9,} "
            f"{iface.crc_errors:>7,} "
            f"{iface.resets:>7,} "
            f"{iface.input_error_rate:>9.2%} "
            f"{iface.output_error_rate:>9.2%}"
        )

    return "\n".join(lines)


def collect(
    host: str,
    username: str,
    password: str,
    device_type: str,
    port: int,
    secret: Optional[str],
) -> List[InterfaceCounters]:
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
    }
    if secret:
        params["secret"] = secret

    logger.info("Connecting to %s", host)
    with ConnectHandler(**params) as conn:
        if secret:
            conn.enable()
        logger.info("Running 'show interfaces'")
        raw = conn.send_command("show interfaces", read_timeout=60)

    return parse_show_interfaces(raw)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Report interface error rates and flag interfaces above threshold."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        metavar="TYPE",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--secret", help="Enable secret")
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.01,
        metavar="RATE",
        help="Error rate threshold, 0.0–1.0 (default: 0.01 = 1%%)",
    )
    parser.add_argument("--output", metavar="FILE", help="Write report to file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not 0.0 <= args.threshold <= 1.0:
        parser.error("--threshold must be between 0.0 and 1.0")

    try:
        interfaces = collect(
            host=args.device,
            username=args.username,
            password=args.password,
            device_type=args.device_type,
            port=args.port,
            secret=args.secret,
        )
    except NetMikoTimeoutException:
        logger.error("Connection timed out: %s", args.device)
        sys.exit(1)
    except NetMikoAuthenticationException:
        logger.error("Authentication failed: %s", args.device)
        sys.exit(1)
    except Exception as exc:
        logger.error("Unexpected error: %s", exc)
        sys.exit(1)

    report = generate_report(args.device, interfaces, threshold=args.threshold)

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(report + "\n")
        logger.info("Report written to %s", args.output)
    else:
        print(report)


if __name__ == "__main__":
    main()
```