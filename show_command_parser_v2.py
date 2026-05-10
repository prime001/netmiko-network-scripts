```python
"""
interface_error_audit.py - Interface Error Threshold Auditor

Purpose:
    Connects to a network device via Netmiko, collects per-interface error
    counters (input errors, output errors, CRC, resets, drops), and flags
    any interface exceeding configurable thresholds. Designed for proactive
    fault detection before error accumulation causes outages or SLA breaches.

Usage:
    python interface_error_audit.py -d 192.168.1.1 -u admin -p secret
    python interface_error_audit.py -d 10.0.0.1 -u admin -p secret \\
        --device-type cisco_ios --crc-threshold 100 --error-threshold 500 \\
        --output results.json --flagged-only

Prerequisites:
    pip install netmiko
    SSH must be enabled on the target device. Read-only credentials suffice.
    Tested against: cisco_ios, cisco_nxos, arista_eos
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass
from typing import Optional

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

SHOW_COMMANDS = {
    "cisco_ios": "show interfaces",
    "cisco_nxos": "show interface",
    "arista_eos": "show interfaces",
}

_IFACE_HEADER = re.compile(r"^(\S+) is (up|down|administratively down)", re.MULTILINE)
_INPUT_ERRORS = re.compile(r"(\d+) input errors")
_OUTPUT_ERRORS = re.compile(r"(\d+) output errors")
_CRC_ERRORS = re.compile(r"(\d+) CRC")
_RESETS = re.compile(r"(\d+) interface resets")
_INPUT_DROPS = re.compile(r"(\d+) no buffer")
_OUTPUT_DROPS = re.compile(r"(\d+) output drops")


@dataclass
class InterfaceErrors:
    name: str
    state: str
    input_errors: int = 0
    output_errors: int = 0
    crc: int = 0
    resets: int = 0
    input_drops: int = 0
    output_drops: int = 0
    flagged: bool = False

    def exceeds(self, error_threshold: int, crc_threshold: int) -> bool:
        return (
            self.input_errors >= error_threshold
            or self.output_errors >= error_threshold
            or self.crc >= crc_threshold
        )


def _extract(pattern: re.Pattern, text: str) -> int:
    m = pattern.search(text)
    return int(m.group(1)) if m else 0


def parse_interface_blocks(raw: str) -> list:
    blocks = re.split(r"(?=^\S+\s+is\s+(?:up|down|administratively down))", raw, flags=re.MULTILINE)
    results = []
    for block in blocks:
        header = _IFACE_HEADER.search(block)
        if not header:
            continue
        results.append(InterfaceErrors(
            name=header.group(1),
            state=header.group(2),
            input_errors=_extract(_INPUT_ERRORS, block),
            output_errors=_extract(_OUTPUT_ERRORS, block),
            crc=_extract(_CRC_ERRORS, block),
            resets=_extract(_RESETS, block),
            input_drops=_extract(_INPUT_DROPS, block),
            output_drops=_extract(_OUTPUT_DROPS, block),
        ))
    return results


def audit_device(
    host: str,
    username: str,
    password: str,
    device_type: str,
    error_threshold: int,
    crc_threshold: int,
    port: int = 22,
    secret: Optional[str] = None,
) -> list:
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
    }
    if secret:
        params["secret"] = secret

    log.info("Connecting to %s (%s)", host, device_type)
    try:
        with ConnectHandler(**params) as conn:
            if secret:
                conn.enable()
            cmd = SHOW_COMMANDS.get(device_type, "show interfaces")
            log.info("Running: %s", cmd)
            raw = conn.send_command(cmd, read_timeout=60)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", host)
        sys.exit(1)

    interfaces = parse_interface_blocks(raw)
    log.info("Parsed %d interfaces", len(interfaces))

    for iface in interfaces:
        iface.flagged = iface.exceeds(error_threshold, crc_threshold)

    return interfaces


def print_report(interfaces: list, error_threshold: int, crc_threshold: int) -> None:
    flagged = [i for i in interfaces if i.flagged]

    print(f"\n{'=' * 62}")
    print(f"Interface Error Audit  —  {len(interfaces)} interfaces checked")
    print(f"Thresholds: errors >= {error_threshold}, CRC >= {crc_threshold}")
    print(f"{'=' * 62}")

    if not flagged:
        print(f"OK  All {len(interfaces)} interfaces within thresholds.\n")
        return

    print(f"FLAGGED: {len(flagged)} interface(s) exceed thresholds:\n")
    header = f"  {'Interface':<26} {'State':<22} {'InErr':>7} {'OutErr':>7} {'CRC':>6} {'Resets':>7}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for iface in flagged:
        print(
            f"  {iface.name:<26} {iface.state:<22} "
            f"{iface.input_errors:>7} {iface.output_errors:>7} "
            f"{iface.crc:>6} {iface.resets:>7}"
        )
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit interface error counters and flag interfaces exceeding thresholds."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("-s", "--secret", help="Enable secret (Cisco IOS)")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(SHOW_COMMANDS.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--error-threshold",
        type=int,
        default=100,
        help="Flag interfaces with input/output errors >= this value (default: 100)",
    )
    parser.add_argument(
        "--crc-threshold",
        type=int,
        default=50,
        help="Flag interfaces with CRC errors >= this value (default: 50)",
    )
    parser.add_argument("--output", help="Write results to this JSON file")
    parser.add_argument(
        "--flagged-only",
        action="store_true",
        help="Limit JSON output to flagged interfaces only",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()

    interfaces = audit_device(
        host=args.device,
        username=args.username,
        password=args.password,
        device_type=args.device_type,
        error_threshold=args.error_threshold,
        crc_threshold=args.crc_threshold,
        port=args.port,
        secret=args.secret,
    )

    print_report(interfaces, args.error_threshold, args.crc_threshold)

    if args.output:
        subset = [i for i in interfaces if not args.flagged_only or i.flagged]
        payload = {"device": args.device, "interfaces": [asdict(i) for i in subset]}
        with open(args.output, "w") as fh:
            json.dump(payload, fh, indent=2)
        log.info("Results written to %s", args.output)

    sys.exit(1 if any(i.flagged for i in interfaces) else 0)


if __name__ == "__main__":
    main()
```