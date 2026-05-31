The user's explicit instruction to output only the script overrides the brainstorming workflow — the requirements are fully specified and user instruction takes highest priority per the skill's own preamble.

"""
interface_error_monitor.py — Poll network interface error counters with threshold alerting.

Connects to a network device via Netmiko and reports per-interface error
statistics: input errors, output errors, CRC errors, and interface resets.
In --watch mode, samples counters at a configurable interval and calculates
per-second error rates, printing an alert marker on interfaces that exceed
the specified threshold.

Supported device types: cisco_ios, cisco_nxos, arista_eos

Usage:
    # Single snapshot
    python interface_error_monitor.py -H 10.0.0.1 -u admin -p secret

    # Continuous watch, alert when input errors exceed 5/s
    python interface_error_monitor.py -H 10.0.0.1 -u admin -p secret \\
        --watch 60 --threshold 5.0

    # Filter to one interface
    python interface_error_monitor.py -H 10.0.0.1 -u admin -p secret \\
        -i GigabitEthernet0/1 -t cisco_nxos

Prerequisites:
    pip install netmiko
"""

import argparse
import getpass
import logging
import re
import sys
import time
from typing import Dict, Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

_PATTERNS = {
    "cisco_ios": {
        "interface": re.compile(r"^(\S+) is (up|down|administratively down)"),
        "input_errors": re.compile(r"(\d+) input errors"),
        "output_errors": re.compile(r"(\d+) output errors"),
        "crc": re.compile(r"(\d+) CRC"),
        "resets": re.compile(r"(\d+) interface resets"),
    },
    "cisco_nxos": {
        "interface": re.compile(r"^(\S+) is (up|down|administratively down)"),
        "input_errors": re.compile(r"(\d+) input error"),
        "output_errors": re.compile(r"(\d+) output error"),
        "crc": re.compile(r"(\d+) CRC"),
        "resets": re.compile(r"(\d+) interface resets"),
    },
    "arista_eos": {
        "interface": re.compile(r"^(\S+) is (up|down|administratively down)"),
        "input_errors": re.compile(r"(\d+) input errors"),
        "output_errors": re.compile(r"(\d+) output errors"),
        "crc": re.compile(r"(\d+) CRC"),
        "resets": re.compile(r"(\d+) interface resets"),
    },
}


def parse_errors(output: str, device_type: str) -> Dict[str, Dict]:
    patterns = _PATTERNS.get(device_type, _PATTERNS["cisco_ios"])
    results: Dict[str, Dict] = {}
    current: Optional[str] = None

    for line in output.splitlines():
        m = patterns["interface"].match(line)
        if m:
            current = m.group(1)
            results[current] = {
                "status": m.group(2),
                "input_errors": 0,
                "output_errors": 0,
                "crc": 0,
                "resets": 0,
            }
            continue
        if current is None:
            continue
        for key in ("input_errors", "output_errors", "crc", "resets"):
            km = patterns[key].search(line)
            if km:
                results[current][key] = int(km.group(1))

    return results


def collect(conn, device_type: str) -> Dict[str, Dict]:
    raw = conn.send_command("show interfaces")
    return parse_errors(raw, device_type)


def compute_rates(
    before: Dict[str, Dict], after: Dict[str, Dict], elapsed: float
) -> Dict[str, Dict[str, float]]:
    rates: Dict[str, Dict[str, float]] = {}
    for intf in after:
        if intf not in before or elapsed <= 0:
            continue
        rates[intf] = {
            k: max(0.0, (after[intf].get(k, 0) - before[intf].get(k, 0)) / elapsed)
            for k in ("input_errors", "output_errors", "crc", "resets")
        }
    return rates


def print_table(
    counters: Dict[str, Dict],
    intf_filter: Optional[str],
    threshold: Optional[float],
    rates: Optional[Dict[str, Dict[str, float]]] = None,
) -> None:
    col = 38
    hdr = f"{'Interface':<{col}} {'Status':<22} {'InErr':>7} {'OutErr':>7} {'CRC':>6} {'Resets':>7}"
    if rates is not None:
        hdr += f"  {'InErr/s':>9}  Alert"
    print(hdr)
    print("-" * len(hdr))

    for intf in sorted(counters):
        if intf_filter and intf_filter.lower() not in intf.lower():
            continue
        d = counters[intf]
        row = (
            f"{intf:<{col}} {d['status']:<22} "
            f"{d['input_errors']:>7} {d['output_errors']:>7} "
            f"{d['crc']:>6} {d['resets']:>7}"
        )
        if rates is not None:
            rate = rates.get(intf, {}).get("input_errors", 0.0)
            flag = "  ***" if threshold is not None and rate > threshold else ""
            row += f"  {rate:>9.2f}{flag}"
        print(row)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Monitor network interface error counters via Netmiko."
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument(
        "-t", "--device-type",
        default="cisco_ios",
        choices=list(_PATTERNS.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("-P", "--port", type=int, default=22, help="SSH port")
    parser.add_argument("-i", "--interface", help="Filter to a specific interface name")
    parser.add_argument(
        "--watch", type=int, metavar="SECONDS",
        help="Continuous polling interval in seconds",
    )
    parser.add_argument(
        "--threshold", type=float, default=5.0,
        help="Input errors/s alert threshold in watch mode (default: 5.0)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = parser.parse_args()

    if args.verbose:
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

    try:
        logger.info("Connecting to %s", args.host)
        with ConnectHandler(**device) as conn:
            if args.watch:
                print(
                    f"Polling {args.host} every {args.watch}s  "
                    f"(threshold: {args.threshold} input errors/s)\n"
                )
                previous = collect(conn, args.device_type)
                while True:
                    time.sleep(args.watch)
                    current = collect(conn, args.device_type)
                    rates = compute_rates(previous, current, args.watch)
                    print_table(current, args.interface, args.threshold, rates)
                    print()
                    previous = current
            else:
                counters = collect(conn, args.device_type)
                print_table(counters, args.interface, None)

    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        logger.error("Connection timed out to %s", args.host)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()