The brainstorming skill doesn't apply here — the user provided a complete specification and explicitly requested only script output. Writing the script directly.

"""
Interface Error Rate Monitor

Connects to a network device via SSH and audits interface error counters
(input errors, output errors, CRC, runts, giants, output drops) against
configurable alert thresholds. Useful for identifying degrading links
before they cause outages.

Usage:
    python interface_error_monitor.py --host 192.168.1.1 \
        --username admin --password secret

    python interface_error_monitor.py --host 10.0.0.1 \
        --username admin --password secret --device-type cisco_ios \
        --input-errors 100 --crc-errors 10 --output-drops 50 \
        --output json

Prerequisites:
    pip install netmiko
"""

import argparse
import json
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
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class InterfaceStats:
    name: str
    input_errors: int = 0
    output_errors: int = 0
    crc: int = 0
    runts: int = 0
    giants: int = 0
    output_drops: int = 0
    violations: List[str] = field(default_factory=list)


def parse_interface_errors(output: str) -> List[InterfaceStats]:
    interfaces: List[InterfaceStats] = []
    current: InterfaceStats | None = None

    for line in output.splitlines():
        iface_match = re.match(
            r"^(\S+)\s+is\s+(?:up|down|administratively down)", line
        )
        if iface_match:
            if current:
                interfaces.append(current)
            current = InterfaceStats(name=iface_match.group(1))
            continue

        if current is None:
            continue

        m = re.search(r"(\d+)\s+input errors.*?(\d+)\s+CRC", line)
        if m:
            current.input_errors = int(m.group(1))
            current.crc = int(m.group(2))

        m = re.search(r"(\d+)\s+runts,\s+(\d+)\s+giants", line)
        if m:
            current.runts = int(m.group(1))
            current.giants = int(m.group(2))

        m = re.search(r"(\d+)\s+output errors", line)
        if m:
            current.output_errors = int(m.group(1))

        m = re.search(r"(\d+)\s+output drops", line)
        if m:
            current.output_drops = int(m.group(1))

    if current:
        interfaces.append(current)

    return interfaces


def apply_thresholds(
    interfaces: List[InterfaceStats],
    input_errors: int,
    output_errors: int,
    crc_errors: int,
    output_drops: int,
) -> List[InterfaceStats]:
    flagged = []
    for iface in interfaces:
        if iface.input_errors > input_errors:
            iface.violations.append(
                f"input_errors={iface.input_errors} > threshold {input_errors}"
            )
        if iface.output_errors > output_errors:
            iface.violations.append(
                f"output_errors={iface.output_errors} > threshold {output_errors}"
            )
        if iface.crc > crc_errors:
            iface.violations.append(f"crc={iface.crc} > threshold {crc_errors}")
        if iface.output_drops > output_drops:
            iface.violations.append(
                f"output_drops={iface.output_drops} > threshold {output_drops}"
            )
        if iface.violations:
            flagged.append(iface)
    return flagged


def render_table(host: str, flagged: List[InterfaceStats]) -> str:
    if not flagged:
        return f"[{host}] All interfaces within thresholds — no errors detected.\n"
    lines = [
        f"[{host}] {len(flagged)} interface(s) exceeded thresholds:",
        f"{'Interface':<35} Violations",
        "-" * 90,
    ]
    for iface in flagged:
        lines.append(f"{iface.name:<35} {'; '.join(iface.violations)}")
    return "\n".join(lines) + "\n"


def render_json(host: str, flagged: List[InterfaceStats]) -> str:
    return json.dumps(
        {
            "host": host,
            "flagged_count": len(flagged),
            "interfaces": [
                {
                    "name": i.name,
                    "input_errors": i.input_errors,
                    "output_errors": i.output_errors,
                    "crc": i.crc,
                    "runts": i.runts,
                    "giants": i.giants,
                    "output_drops": i.output_drops,
                    "violations": i.violations,
                }
                for i in flagged
            ],
        },
        indent=2,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit interface error counters against configurable thresholds."
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--input-errors",
        type=int,
        default=0,
        metavar="N",
        help="Alert when input errors exceed N (default: 0)",
    )
    parser.add_argument(
        "--output-errors",
        type=int,
        default=0,
        metavar="N",
        help="Alert when output errors exceed N (default: 0)",
    )
    parser.add_argument(
        "--crc-errors",
        type=int,
        default=0,
        metavar="N",
        help="Alert when CRC errors exceed N (default: 0)",
    )
    parser.add_argument(
        "--output-drops",
        type=int,
        default=0,
        metavar="N",
        help="Alert when output drops exceed N (default: 0)",
    )
    parser.add_argument(
        "--output",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    log.info("Connecting to %s (%s)", args.host, args.device_type)
    try:
        with ConnectHandler(
            device_type=args.device_type,
            host=args.host,
            username=args.username,
            password=args.password,
            port=args.port,
        ) as conn:
            log.info("Connected — retrieving interface statistics")
            raw = conn.send_command("show interfaces", read_timeout=60)
    except NetMikoAuthenticationException:
        log.error("Authentication failed for %s", args.host)
        return 1
    except NetMikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        return 1
    except Exception as exc:
        log.error("Unexpected error connecting to %s: %s", args.host, exc)
        return 1

    interfaces = parse_interface_errors(raw)
    log.info("Parsed %d interfaces", len(interfaces))

    flagged = apply_thresholds(
        interfaces,
        input_errors=args.input_errors,
        output_errors=args.output_errors,
        crc_errors=args.crc_errors,
        output_drops=args.output_drops,
    )
    log.info("%d interface(s) exceeded thresholds", len(flagged))

    if args.output == "json":
        print(render_json(args.host, flagged))
    else:
        print(render_table(args.host, flagged))

    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())