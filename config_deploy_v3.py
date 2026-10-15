```python
"""
interface_error_audit.py - Audit network device interfaces for elevated error counters.

Purpose:
    Connects to a Cisco IOS/IOS-XE/NX-OS device and inspects all interfaces
    for input errors, CRC errors, runts, giants, and output/input drops.
    Reports interfaces exceeding configurable thresholds, making it easy to
    spot degraded links before they cause outages.

Usage:
    python interface_error_audit.py --host 10.0.0.1 --username admin --password secret
    python interface_error_audit.py --host 10.0.0.1 -u admin -p secret \
        --crc-threshold 5 --drops-threshold 50 --device-type cisco_nxos
    python interface_error_audit.py --host 10.0.0.1 -u admin --show-clean

Prerequisites:
    pip install netmiko
    Credentials require at least read-only (privilege-exec) access.
    Supported device types: cisco_ios, cisco_xe, cisco_nxos
"""

import argparse
import getpass
import logging
import re
import sys
from dataclasses import dataclass, field
from typing import List

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class InterfaceErrors:
    name: str
    input_errors: int = 0
    crc: int = 0
    runts: int = 0
    giants: int = 0
    output_drops: int = 0
    input_drops: int = 0
    flagged: bool = False
    reasons: List[str] = field(default_factory=list)


def parse_interface_errors(output: str) -> List[InterfaceErrors]:
    """Extract error counters from 'show interfaces' output."""
    interfaces = []
    current = None

    for line in output.splitlines():
        iface_match = re.match(
            r'^(\S+)\s+is\s+(?:up|down|administratively down)', line
        )
        if iface_match:
            if current:
                interfaces.append(current)
            current = InterfaceErrors(name=iface_match.group(1))
            continue

        if current is None:
            continue

        m = re.search(r'(\d+)\s+input errors', line)
        if m:
            current.input_errors = int(m.group(1))
        m = re.search(r'(\d+)\s+CRC', line)
        if m:
            current.crc = int(m.group(1))
        m = re.search(r'(\d+)\s+runts', line)
        if m:
            current.runts = int(m.group(1))
        m = re.search(r'(\d+)\s+giants', line)
        if m:
            current.giants = int(m.group(1))
        m = re.search(r'(\d+)\s+output drops', line)
        if m:
            current.output_drops = int(m.group(1))
        # NX-OS reports input drops separately
        m = re.search(r'(\d+)\s+input drops', line)
        if m:
            current.input_drops = int(m.group(1))

    if current:
        interfaces.append(current)

    return interfaces


def apply_thresholds(
    interfaces: List[InterfaceErrors],
    input_errors: int,
    crc: int,
    runts: int,
    giants: int,
    drops: int,
) -> List[InterfaceErrors]:
    """Flag interfaces that exceed any non-zero threshold."""
    checks = [
        ("input_errors", input_errors),
        ("crc", crc),
        ("runts", runts),
        ("giants", giants),
        ("output_drops", drops),
        ("input_drops", drops),
    ]
    for iface in interfaces:
        for attr, threshold in checks:
            value = getattr(iface, attr)
            if threshold > 0 and value >= threshold:
                iface.flagged = True
                iface.reasons.append(f"{attr}={value}")
    return interfaces


def print_report(
    host: str, interfaces: List[InterfaceErrors], show_clean: bool
) -> int:
    """Print audit results; returns count of flagged interfaces."""
    flagged = [i for i in interfaces if i.flagged]
    clean = [i for i in interfaces if not i.flagged]

    print(f"\n{'=' * 62}")
    print(f"Interface Error Audit: {host}")
    print(f"Total interfaces: {len(interfaces)}  |  Flagged: {len(flagged)}")
    print(f"{'=' * 62}")

    if flagged:
        print("\n[WARN] FLAGGED INTERFACES:")
        print(f"  {'Interface':<34} Reason(s)")
        print(f"  {'-' * 56}")
        for iface in flagged:
            print(f"  {iface.name:<34} {', '.join(iface.reasons)}")
    else:
        print("\n[OK] No interfaces exceed error thresholds.")

    if show_clean and clean:
        print(f"\n[OK] Clean interfaces ({len(clean)}):")
        for iface in clean:
            print(f"  {iface.name}")

    print()
    return len(flagged)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Audit Cisco device interfaces for elevated error counters."
    )
    p.add_argument("--host", required=True, help="Device hostname or IP")
    p.add_argument("--username", "-u", required=True, help="SSH username")
    p.add_argument(
        "--password", "-p", default=None,
        help="SSH password (prompted if omitted)",
    )
    p.add_argument(
        "--device-type", default="cisco_ios",
        choices=["cisco_ios", "cisco_xe", "cisco_nxos"],
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--input-errors-threshold", type=int, default=10, metavar="N",
        help="Flag if input errors >= N (default: 10; 0=disable)",
    )
    p.add_argument(
        "--crc-threshold", type=int, default=5, metavar="N",
        help="Flag if CRC errors >= N (default: 5; 0=disable)",
    )
    p.add_argument(
        "--runts-threshold", type=int, default=0, metavar="N",
        help="Flag if runts >= N (default: 0=disabled)",
    )
    p.add_argument(
        "--giants-threshold", type=int, default=0, metavar="N",
        help="Flag if giants >= N (default: 0=disabled)",
    )
    p.add_argument(
        "--drops-threshold", type=int, default=100, metavar="N",
        help="Flag if output/input drops >= N (default: 100; 0=disable)",
    )
    p.add_argument(
        "--show-clean", action="store_true",
        help="Also list interfaces with no flagged errors",
    )
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.host}: "
    )

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": password,
        "port": args.port,
    }

    log.info("Connecting to %s (%s)", args.host, args.device_type)
    try:
        with ConnectHandler(**device) as conn:
            log.info("Connected. Running 'show interfaces'...")
            output = conn.send_command("show interfaces", read_timeout=60)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        return 1
    except Exception as exc:
        log.error("Unexpected connection error: %s", exc)
        return 1

    interfaces = parse_interface_errors(output)
    if not interfaces:
        log.warning("No interface data parsed — verify device output format.")
        return 1

    log.info("Parsed %d interfaces.", len(interfaces))

    interfaces = apply_thresholds(
        interfaces,
        input_errors=args.input_errors_threshold,
        crc=args.crc_threshold,
        runts=args.runts_threshold,
        giants=args.giants_threshold,
        drops=args.drops_threshold,
    )

    flagged_count = print_report(args.host, interfaces, args.show_clean)
    # Exit 2 when flagged interfaces found so callers can distinguish from errors
    return 0 if flagged_count == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
```