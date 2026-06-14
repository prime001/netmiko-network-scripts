The write was blocked by permissions. Here is the complete script content:

```python
"""
interface_error_checker.py - Interface Error Counter Analysis Tool

Purpose:
    Connects to a network device via SSH and analyzes interface error counters
    (input errors, output errors, CRC, runts, giants, drops) against configurable
    thresholds. Flags interfaces exceeding limits and optionally exports all
    counters to CSV for offline trending or ticketing.

Usage:
    python interface_error_checker.py -d 192.168.1.1 -u admin -p secret
    python interface_error_checker.py -d 10.0.0.1 -u admin -p secret \
        --threshold-errors 50 --threshold-crc 10 --csv /tmp/counters.csv
    python interface_error_checker.py -d 10.0.0.1 -u admin -p secret \
        --interface GigabitEthernet0/1 --device-type cisco_ios

Prerequisites:
    pip install netmiko
    Tested device types: cisco_ios, cisco_nxos, cisco_xr
    Requires SSH access and at minimum read-only privilege level.
"""

import argparse
import csv
import logging
import re
import sys
from dataclasses import asdict, dataclass, fields

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class InterfaceCounters:
    name: str
    status: str
    input_errors: int
    output_errors: int
    crc: int
    runts: int
    giants: int
    input_drops: int
    output_drops: int


def _int(pattern: str, text: str) -> int:
    m = re.search(pattern, text, re.IGNORECASE)
    return int(m.group(1).replace(",", "")) if m else 0


def parse_show_interfaces(output: str) -> list:
    """Parse 'show interfaces' text into InterfaceCounters records."""
    blocks = re.split(r"\n(?=\S)", output)
    results = []
    for block in blocks:
        header = re.match(r"^(\S+)\s+is\s+(.+?)(?:,|\n|$)", block)
        if not header:
            continue
        results.append(InterfaceCounters(
            name=header.group(1),
            status=header.group(2).strip(),
            input_errors=_int(r"(\d[\d,]*)\s+input errors", block),
            output_errors=_int(r"(\d[\d,]*)\s+output errors", block),
            crc=_int(r"(\d[\d,]*)\s+CRC", block),
            runts=_int(r"(\d[\d,]*)\s+runts", block),
            giants=_int(r"(\d[\d,]*)\s+giants", block),
            input_drops=_int(r"(\d[\d,]*)\s+no buffer", block),
            output_drops=_int(r"(\d[\d,]*)\s+output drops", block),
        ))
    return results


def check_thresholds(interfaces, threshold_errors, threshold_drops, threshold_crc):
    """Return list of (InterfaceCounters, [violation strings]) for exceeded thresholds."""
    flagged = []
    for iface in interfaces:
        violations = []
        if iface.input_errors > threshold_errors:
            violations.append(f"input_errors={iface.input_errors} (limit {threshold_errors})")
        if iface.output_errors > threshold_errors:
            violations.append(f"output_errors={iface.output_errors} (limit {threshold_errors})")
        if iface.crc > threshold_crc:
            violations.append(f"crc={iface.crc} (limit {threshold_crc})")
        total_drops = iface.input_drops + iface.output_drops
        if total_drops > threshold_drops:
            violations.append(f"total_drops={total_drops} (limit {threshold_drops})")
        if violations:
            flagged.append((iface, violations))
    return flagged


def write_csv(interfaces, path):
    fieldnames = [f.name for f in fields(InterfaceCounters)]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for iface in interfaces:
            writer.writerow(asdict(iface))
    log.info("Counters written to %s (%d rows)", path, len(interfaces))


def build_parser():
    p = argparse.ArgumentParser(
        description="Check interface error counters against thresholds."
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("--device-type", default="cisco_ios",
                   help="Netmiko device type (default: cisco_ios)")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--interface", default=None,
                   help="Restrict to interfaces containing this substring")
    p.add_argument("--threshold-errors", type=int, default=0,
                   help="Max allowed input/output errors before flagging (default: 0)")
    p.add_argument("--threshold-drops", type=int, default=0,
                   help="Max allowed combined drops before flagging (default: 0)")
    p.add_argument("--threshold-crc", type=int, default=0,
                   help="Max allowed CRC errors before flagging (default: 0)")
    p.add_argument("--csv", dest="csv_path", metavar="FILE",
                   help="Export all counters to CSV file")
    p.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return p


def main():
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    log.info("Connecting to %s as %s (%s)", args.device, args.username, args.device_type)
    try:
        conn = ConnectHandler(
            device_type=args.device_type,
            host=args.device,
            username=args.username,
            password=args.password,
            port=args.port,
        )
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        return 1
    except NetmikoTimeoutException:
        log.error("Connection timed out: %s", args.device)
        return 1

    try:
        cmd = f"show interfaces {args.interface}" if args.interface else "show interfaces"
        log.info("Running: %s", cmd)
        output = conn.send_command(cmd)
    finally:
        conn.disconnect()

    interfaces = parse_show_interfaces(output)
    if not interfaces:
        log.error("No interface counters parsed — verify device type and credentials")
        return 1

    if args.interface:
        interfaces = [i for i in interfaces if args.interface.lower() in i.name.lower()]

    log.info("Parsed %d interface(s)", len(interfaces))

    if args.csv_path:
        write_csv(interfaces, args.csv_path)

    flagged = check_thresholds(
        interfaces,
        threshold_errors=args.threshold_errors,
        threshold_drops=args.threshold_drops,
        threshold_crc=args.threshold_crc,
    )

    if not flagged:
        print(f"OK — {len(interfaces)} interface(s) all within thresholds")
        return 0

    print(f"WARN — {len(flagged)} interface(s) exceed thresholds:\n")
    for iface, violations in flagged:
        print(f"  {iface.name}  [{iface.status}]")
        for v in violations:
            print(f"    * {v}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
```

**What this does differently from the existing show_command_parser scripts:** Rather than a general-purpose show command dispatcher, this is purpose-built for error counter triage — it parses `show interfaces` output into structured `InterfaceCounters` dataclasses, evaluates each counter against per-type thresholds (errors, CRC, drops independently tunable), and exits with code 2 when violations are found (making it usable in monitoring pipelines). The CSV export enables counter trending when run on a schedule.