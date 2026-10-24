The target repo isn't in `/opt/NetAutoCommitter` — this is a standalone GitHub portfolio repo. The prompt asks for raw script output only, so here it is:

```
#!/usr/bin/env python3
"""
interface_error_monitor.py - Network interface error counter monitor

Purpose:
    Connects to a Cisco IOS/IOS-XE/NX-OS device via SSH and reports
    interface error counters (input errors, CRC, output errors, drops).
    Optionally samples twice over a configurable interval to compute
    per-second error rates. Interfaces exceeding configurable thresholds
    are flagged with an asterisk in the output.

Usage:
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret \
        --interval 30 --crc-threshold 5 --in-err-threshold 10
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret \
        --device-type cisco_nxos --all

Prerequisites:
    pip install netmiko
    SSH access to target device; 'show interfaces' must be available.
"""

import argparse
import logging
import re
import sys
import time
from typing import Dict, Optional

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

Counters = Dict[str, int]
IfaceData = Dict[str, Counters]


def parse_interface_errors(output: str) -> IfaceData:
    """Parse 'show interfaces' output into per-interface error counter dicts."""
    interfaces: IfaceData = {}
    current = None

    for line in output.splitlines():
        iface_match = re.match(r'^(\S+)\s+is\s+(?:up|down|administratively down)', line)
        if iface_match:
            current = iface_match.group(1)
            interfaces[current] = {
                "input_errors": 0,
                "output_errors": 0,
                "crc": 0,
                "input_drops": 0,
                "output_drops": 0,
            }
            continue

        if current is None:
            continue

        patterns = [
            (r'(\d+)\s+input errors', "input_errors"),
            (r'(\d+)\s+CRC', "crc"),
            (r'(\d+)\s+output errors', "output_errors"),
            (r'(\d+)\s+no buffer', "input_drops"),
            (r'(\d+)\s+output drops', "output_drops"),
        ]
        for pattern, key in patterns:
            m = re.search(pattern, line)
            if m:
                interfaces[current][key] = int(m.group(1))

    return interfaces


def compute_rates(
    baseline: IfaceData, sample: IfaceData, interval: float
) -> Dict[str, Dict[str, float]]:
    """Return per-second delta rates between two counter snapshots."""
    rates: Dict[str, Dict[str, float]] = {}
    for iface, counters in sample.items():
        if iface not in baseline:
            continue
        rates[iface] = {
            key: max(0, counters[key] - baseline[iface].get(key, 0)) / interval
            for key in counters
        }
    return rates


def is_flagged(counters: Counters, args: argparse.Namespace) -> bool:
    return (
        counters["input_errors"] > args.in_err_threshold
        or counters["crc"] > args.crc_threshold
        or counters["output_errors"] > args.out_err_threshold
    )


def print_report(
    data: IfaceData,
    rates: Optional[Dict[str, Dict[str, float]]],
    args: argparse.Namespace,
) -> int:
    """Print the error report table; return count of flagged interfaces."""
    col = f"{'Interface':<35} {'InErr':>8} {'CRC':>7} {'OutErr':>8} {'InDrop':>8} {'OutDrop':>9}"
    print(f"\nInterface error report — {args.host}")
    print(col)
    print("-" * len(col))

    flagged = 0
    for iface, ctr in sorted(data.items()):
        flag = " *" if is_flagged(ctr, args) else ""
        if flag:
            flagged += 1
        row = (
            f"{iface:<35} {ctr['input_errors']:>8} {ctr['crc']:>7}"
            f" {ctr['output_errors']:>8} {ctr['input_drops']:>8} {ctr['output_drops']:>9}{flag}"
        )
        if rates and iface in rates:
            r = rates[iface]
            row += (
                f"  [{r['input_errors']:.2f}/s in"
                f" {r['crc']:.2f}/s crc"
                f" {r['output_errors']:.2f}/s out]"
            )
        print(row)

    if flagged:
        print(
            f"\n  * {flagged} interface(s) exceed thresholds"
            f" (in>{args.in_err_threshold}"
            f" crc>{args.crc_threshold}"
            f" out>{args.out_err_threshold})"
        )
    return flagged


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Report interface error counters from a network device"
    )
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("--secret", default="", help="Enable secret")
    p.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--interval", type=float, default=0, metavar="SECS",
        help="Sampling interval in seconds for rate calculation; 0 = single snapshot",
    )
    p.add_argument(
        "--in-err-threshold", type=int, default=0, metavar="N",
        help="Flag interfaces with input errors > N (default: 0)",
    )
    p.add_argument(
        "--crc-threshold", type=int, default=0, metavar="N",
        help="Flag interfaces with CRC errors > N (default: 0)",
    )
    p.add_argument(
        "--out-err-threshold", type=int, default=0, metavar="N",
        help="Flag interfaces with output errors > N (default: 0)",
    )
    p.add_argument(
        "--all", action="store_true",
        help="Show all interfaces, not just those with non-zero counters",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    device_params = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }
    if args.secret:
        device_params["secret"] = args.secret

    log.info("Connecting to %s (%s)", args.host, args.device_type)
    try:
        with ConnectHandler(**device_params) as conn:
            if args.secret:
                conn.enable()

            log.info("Collecting interface counters (snapshot 1)...")
            baseline_raw = conn.send_command("show interfaces", read_timeout=60)
            baseline = parse_interface_errors(baseline_raw)

            rates = None
            display = baseline

            if args.interval > 0:
                log.info("Waiting %.0fs before second snapshot...", args.interval)
                time.sleep(args.interval)
                log.info("Collecting interface counters (snapshot 2)...")
                sample_raw = conn.send_command("show interfaces", read_timeout=60)
                sample = parse_interface_errors(sample_raw)
                rates = compute_rates(baseline, sample, args.interval)
                display = sample

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 2
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", args.host)
        return 3
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        return 1

    if not args.all:
        display = {k: v for k, v in display.items() if any(v.values())}

    if not display:
        print(f"No interface errors found on {args.host}")
        return 0

    flagged = print_report(display, rates, args)
    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
```