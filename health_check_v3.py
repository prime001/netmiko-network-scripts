```python
"""
Interface Error Rate Monitor
============================
Connects to a network device via Netmiko, collects interface error counters
(input errors, output errors, CRC errors, resets), and flags any interface
whose error count exceeds configurable thresholds.

Usage:
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -d 10.0.0.1 -u admin -p secret \
        --device-type cisco_ios --input-errors 50 --crc-errors 10 \
        --output-file results.json

Prerequisites:
    pip install netmiko

Supported device types: cisco_ios, cisco_nxos, cisco_xr, arista_eos, juniper_junos
"""

import argparse
import getpass
import json
import logging
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import Optional

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


@dataclass
class InterfaceErrors:
    name: str
    input_errors: int = 0
    output_errors: int = 0
    crc_errors: int = 0
    resets: int = 0
    flagged: bool = False
    reasons: list = field(default_factory=list)


def parse_cisco_interface_errors(output: str) -> list[InterfaceErrors]:
    results = []
    current: Optional[InterfaceErrors] = None

    for line in output.splitlines():
        iface_match = re.match(r"^(\S+) is (up|down|administratively down)", line)
        if iface_match:
            if current:
                results.append(current)
            current = InterfaceErrors(name=iface_match.group(1))
            continue

        if current is None:
            continue

        m = re.search(r"(\d+) input errors", line)
        if m:
            current.input_errors = int(m.group(1))

        m = re.search(r"(\d+) CRC", line)
        if m:
            current.crc_errors = int(m.group(1))

        m = re.search(r"(\d+) output errors", line)
        if m:
            current.output_errors = int(m.group(1))

        m = re.search(r"(\d+) interface resets", line)
        if m:
            current.resets = int(m.group(1))

    if current:
        results.append(current)

    return results


def apply_thresholds(
    interfaces: list[InterfaceErrors],
    input_threshold: int,
    output_threshold: int,
    crc_threshold: int,
    reset_threshold: int,
) -> list[InterfaceErrors]:
    for iface in interfaces:
        if iface.input_errors > input_threshold:
            iface.flagged = True
            iface.reasons.append(f"input_errors={iface.input_errors} > {input_threshold}")
        if iface.output_errors > output_threshold:
            iface.flagged = True
            iface.reasons.append(f"output_errors={iface.output_errors} > {output_threshold}")
        if iface.crc_errors > crc_threshold:
            iface.flagged = True
            iface.reasons.append(f"crc_errors={iface.crc_errors} > {crc_threshold}")
        if iface.resets > reset_threshold:
            iface.flagged = True
            iface.reasons.append(f"resets={iface.resets} > {reset_threshold}")
    return interfaces


def collect_errors(args) -> list[InterfaceErrors]:
    device = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "timeout": args.timeout,
    }

    logger.info("Connecting to %s (%s)", args.device, args.device_type)
    with ConnectHandler(**device) as conn:
        logger.info("Connected. Collecting interface counters...")
        output = conn.send_command("show interfaces", read_timeout=60)

    return parse_cisco_interface_errors(output)


def print_report(interfaces: list[InterfaceErrors], device: str) -> None:
    flagged = [i for i in interfaces if i.flagged]
    total = len(interfaces)

    print(f"\n=== Interface Error Report: {device} ===")
    print(f"Checked {total} interface(s), {len(flagged)} flagged\n")

    if not flagged:
        print("No interfaces exceed error thresholds.")
        return

    for iface in flagged:
        print(f"  FLAGGED  {iface.name}")
        for reason in iface.reasons:
            print(f"           - {reason}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Monitor interface error counters against configurable thresholds."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument(
        "--device-type", default="cisco_ios",
        choices=["cisco_ios", "cisco_nxos", "cisco_xr", "arista_eos", "juniper_junos"],
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--timeout", type=int, default=30, help="SSH timeout in seconds")
    parser.add_argument("--input-errors", type=int, default=100, metavar="N",
                        help="Flag interface if input errors exceed N (default: 100)")
    parser.add_argument("--output-errors", type=int, default=100, metavar="N",
                        help="Flag interface if output errors exceed N (default: 100)")
    parser.add_argument("--crc-errors", type=int, default=0, metavar="N",
                        help="Flag interface if CRC errors exceed N (default: 0)")
    parser.add_argument("--resets", type=int, default=5, metavar="N",
                        help="Flag interface if interface resets exceed N (default: 5)")
    parser.add_argument("--output-file", metavar="PATH",
                        help="Write full results as JSON to this file")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    try:
        interfaces = collect_errors(args)
    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        logger.error("Connection timed out to %s", args.device)
        sys.exit(1)
    except Exception as exc:
        logger.error("Unexpected error: %s", exc)
        sys.exit(1)

    interfaces = apply_thresholds(
        interfaces,
        args.input_errors,
        args.output_errors,
        args.crc_errors,
        args.resets,
    )

    print_report(interfaces, args.device)

    if args.output_file:
        payload = {
            "device": args.device,
            "thresholds": {
                "input_errors": args.input_errors,
                "output_errors": args.output_errors,
                "crc_errors": args.crc_errors,
                "resets": args.resets,
            },
            "interfaces": [asdict(i) for i in interfaces],
        }
        with open(args.output_file, "w") as fh:
            json.dump(payload, fh, indent=2)
        logger.info("Results written to %s", args.output_file)

    flagged_count = sum(1 for i in interfaces if i.flagged)
    sys.exit(1 if flagged_count else 0)


if __name__ == "__main__":
    main()
```