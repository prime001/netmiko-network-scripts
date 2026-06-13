```python
"""
interface_error_monitor.py - Interface Error Rate Monitor

Connects to a network device via Netmiko, samples interface error counters
over a configurable interval, calculates per-second error rates, and flags
interfaces exceeding configurable thresholds.

Usage:
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret \
        --device-type cisco_ios --interval 30 --samples 3 \
        --error-threshold 10 --drop-threshold 5

Prerequisites:
    pip install netmiko
    Supported device types: cisco_ios, cisco_nxos, cisco_xe, arista_eos, juniper_junos
"""

import argparse
import getpass
import logging
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class InterfaceCounters:
    name: str
    input_errors: int = 0
    crc_errors: int = 0
    output_drops: int = 0
    input_drops: int = 0
    timestamp: float = field(default_factory=time.time)


def parse_cisco_interface_counters(output: str) -> List[InterfaceCounters]:
    """Extract error counters from 'show interfaces' output for IOS/NX-OS/XE."""
    interfaces = []
    current_iface: Optional[InterfaceCounters] = None

    for line in output.splitlines():
        line = line.strip()
        if line and line[0].isalpha() and "is " in line and not line.startswith(" "):
            if current_iface:
                interfaces.append(current_iface)
            name = line.split()[0]
            current_iface = InterfaceCounters(name=name)
        if current_iface is None:
            continue
        if "input errors" in line:
            try:
                current_iface.input_errors = int(line.split()[0])
            except (ValueError, IndexError):
                pass
        if "CRC" in line or "crc" in line.lower():
            parts = line.split(",")
            for part in parts:
                if "CRC" in part or "crc" in part.lower():
                    try:
                        current_iface.crc_errors = int(part.strip().split()[0])
                    except (ValueError, IndexError):
                        pass
        if "output drop" in line.lower() or "output discard" in line.lower():
            try:
                current_iface.output_drops = int(line.strip().split()[0])
            except (ValueError, IndexError):
                pass
        if "input drop" in line.lower():
            try:
                current_iface.input_drops = int(line.strip().split()[0])
            except (ValueError, IndexError):
                pass

    if current_iface:
        interfaces.append(current_iface)
    return interfaces


def collect_sample(connection, device_type: str) -> List[InterfaceCounters]:
    """Send the appropriate show command and return parsed counters."""
    if "juniper" in device_type:
        output = connection.send_command("show interfaces detail")
    else:
        output = connection.send_command("show interfaces", read_timeout=60)
    return parse_cisco_interface_counters(output)


def compute_rates(
    first: InterfaceCounters,
    second: InterfaceCounters,
    elapsed: float,
) -> Dict[str, float]:
    if elapsed <= 0:
        return {}
    return {
        "input_errors_per_sec": (second.input_errors - first.input_errors) / elapsed,
        "crc_errors_per_sec": (second.crc_errors - first.crc_errors) / elapsed,
        "output_drops_per_sec": (second.output_drops - first.output_drops) / elapsed,
        "input_drops_per_sec": (second.input_drops - first.input_drops) / elapsed,
    }


def run_monitor(args) -> int:
    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "timeout": 30,
    }

    log.info("Connecting to %s (%s)", args.host, args.device_type)
    try:
        connection = ConnectHandler(**device)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.host)
        return 1
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        return 1

    log.info(
        "Collecting %d samples with %ds interval", args.samples, args.interval
    )
    all_samples: List[List[InterfaceCounters]] = []

    try:
        for i in range(args.samples):
            log.info("Sample %d/%d", i + 1, args.samples)
            sample = collect_sample(connection, args.device_type)
            all_samples.append(sample)
            if i < args.samples - 1:
                time.sleep(args.interval)
    finally:
        connection.disconnect()

    if len(all_samples) < 2:
        log.warning("Need at least 2 samples to compute rates; collected %d", len(all_samples))
        return 0

    first_by_name = {c.name: c for c in all_samples[0]}
    last_by_name = {c.name: c for c in all_samples[-1]}
    elapsed = (args.samples - 1) * args.interval

    flagged = []
    clean = []

    for name, last in sorted(last_by_name.items()):
        first = first_by_name.get(name)
        if not first:
            continue
        rates = compute_rates(first, last, elapsed)
        errors_per_sec = rates.get("input_errors_per_sec", 0) + rates.get("crc_errors_per_sec", 0)
        drops_per_sec = rates.get("output_drops_per_sec", 0) + rates.get("input_drops_per_sec", 0)

        if errors_per_sec >= args.error_threshold or drops_per_sec >= args.drop_threshold:
            flagged.append((name, rates, errors_per_sec, drops_per_sec))
        else:
            clean.append(name)

    print(f"\n{'='*60}")
    print(f"Interface Error Report — {args.host}")
    print(f"Elapsed: {elapsed}s over {args.samples} samples")
    print(f"{'='*60}")

    if flagged:
        print(f"\n[FLAGGED] {len(flagged)} interface(s) exceed thresholds:\n")
        for name, rates, err_rate, drop_rate in flagged:
            print(f"  {name}")
            print(f"    errors/s : {err_rate:.2f}  (threshold {args.error_threshold})")
            print(f"    drops/s  : {drop_rate:.2f}  (threshold {args.drop_threshold})")
    else:
        print("\n[OK] No interfaces exceed thresholds.")

    print(f"\n{len(clean)} interface(s) clean, {len(flagged)} flagged.\n")
    return 1 if flagged else 0


def main():
    parser = argparse.ArgumentParser(
        description="Monitor interface error rates on network devices via Netmiko."
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=["cisco_ios", "cisco_nxos", "cisco_xe", "arista_eos", "juniper_junos"],
        help="Netmiko device type",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--interval", type=int, default=30, help="Seconds between samples (default: 30)"
    )
    parser.add_argument(
        "--samples", type=int, default=3, help="Number of samples to collect (default: 3)"
    )
    parser.add_argument(
        "--error-threshold",
        type=float,
        default=10.0,
        metavar="N",
        help="Input+CRC errors/sec to flag (default: 10)",
    )
    parser.add_argument(
        "--drop-threshold",
        type=float,
        default=5.0,
        metavar="N",
        help="Input+output drops/sec to flag (default: 5)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.password is None:
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    if args.samples < 2:
        log.error("--samples must be >= 2")
        sys.exit(1)

    sys.exit(run_monitor(args))


if __name__ == "__main__":
    main()
```