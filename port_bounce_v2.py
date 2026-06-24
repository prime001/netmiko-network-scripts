Interface Error Counter Monitor
================================
Connects to a Cisco IOS/IOS-XE device via SSH and polls interface error
counters (input errors, output errors, CRC, runts, giants, resets). Reports
any interface whose worst counter meets or exceeds a configurable threshold.
Supports one-shot mode or continuous polling with a configurable interval.

Usage:
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret \
        --threshold 100 --interval 60 --count 10
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret \
        --interface GigabitEthernet0/1

Prerequisites:
    pip install netmiko
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
import time

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

_INTF_HEADER = re.compile(r"^(\S+) is (up|down|administratively down)", re.MULTILINE)
_COUNTERS = {
    "input_errors": re.compile(r"(\d+) input errors"),
    "output_errors": re.compile(r"(\d+) output errors"),
    "crc": re.compile(r"(\d+) CRC"),
    "runts": re.compile(r"(\d+) runts"),
    "giants": re.compile(r"(\d+) giants"),
    "resets": re.compile(r"(\d+) interface resets"),
}


def parse_interfaces(output: str) -> list[dict]:
    """Split 'show interfaces' output into per-interface dicts with error counters."""
    interfaces = []
    for block in re.split(r"\n(?=\S)", output):
        m = _INTF_HEADER.match(block)
        if not m:
            continue
        entry: dict = {"name": m.group(1), "status": m.group(2)}
        for key, pattern in _COUNTERS.items():
            hit = pattern.search(block)
            entry[key] = int(hit.group(1)) if hit else 0
        interfaces.append(entry)
    return interfaces


def flagged_interfaces(interfaces: list[dict], threshold: int) -> list[dict]:
    """Return interfaces where any error counter meets or exceeds threshold."""
    result = []
    for intf in interfaces:
        counters = {k: v for k, v in intf.items() if k not in ("name", "status")}
        worst = max(counters, key=lambda k: counters[k])
        if counters[worst] >= threshold:
            result.append({**intf, "worst": worst, "worst_value": counters[worst]})
    return result


def print_report(flagged: list[dict], threshold: int) -> None:
    if not flagged:
        log.info("No interfaces exceed threshold of %d", threshold)
        return
    header = f"{'Interface':<32} {'Status':<22} {'Worst Counter':<18} {'Value':>8}"
    print(f"\n{header}")
    print("-" * len(header))
    for intf in sorted(flagged, key=lambda x: x["worst_value"], reverse=True):
        print(
            f"{intf['name']:<32} {intf['status']:<22} "
            f"{intf['worst']:<18} {intf['worst_value']:>8}"
        )
    print()


def poll(conn, threshold: int, interface: str | None) -> None:
    cmd = f"show interfaces {interface}" if interface else "show interfaces"
    output = conn.send_command(cmd, read_timeout=60)
    interfaces = parse_interfaces(output)
    if not interfaces:
        log.warning("No interfaces parsed from output — check device type or command")
        return
    log.info("Checked %d interface(s)", len(interfaces))
    print_report(flagged_interfaces(interfaces, threshold), threshold)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Monitor Cisco interface error counters and alert on threshold breaches."
    )
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("--secret", default="", help="Enable secret (if required)")
    p.add_argument(
        "--device-type", default="cisco_ios", help="Netmiko device type (default: cisco_ios)"
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--threshold",
        type=int,
        default=50,
        help="Alert when any error counter reaches this value (default: 50)",
    )
    p.add_argument(
        "--interval",
        type=int,
        default=0,
        help="Polling interval in seconds; 0 = run once (default: 0)",
    )
    p.add_argument(
        "--count",
        type=int,
        default=0,
        help="Max poll cycles; 0 = unlimited — only applies when --interval > 0 (default: 0)",
    )
    p.add_argument(
        "--interface",
        default=None,
        help="Scope to a single interface name (e.g. GigabitEthernet0/1)",
    )
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "secret": args.secret,
        "port": args.port,
    }

    try:
        log.info("Connecting to %s", args.host)
        conn = ConnectHandler(**device)
        if args.secret:
            conn.enable()
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out reaching %s", args.host)
        sys.exit(1)
    except Exception as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    try:
        if args.interval == 0:
            poll(conn, args.threshold, args.interface)
        else:
            cycle = 0
            while True:
                cycle += 1
                log.info("Poll cycle %d", cycle)
                poll(conn, args.threshold, args.interface)
                if args.count and cycle >= args.count:
                    break
                time.sleep(args.interval)
    except KeyboardInterrupt:
        log.info("Stopped by user")
    finally:
        conn.disconnect()
        log.info("Disconnected from %s", args.host)