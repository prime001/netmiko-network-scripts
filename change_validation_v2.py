interface_error_monitor.py - Network Interface Error Rate Monitor

Purpose:
    Connects to a Cisco IOS/IOS-XE/NX-OS device via Netmiko, collects
    interface input/output counters, and flags any interface whose error
    rate exceeds a configurable threshold.  Useful after change windows
    or overnight to surface CRC storms, duplex mismatches, or flapping
    links before they impact users.

Usage:
    python interface_error_monitor.py --host 10.0.0.1 --user admin
    python interface_error_monitor.py --host 10.0.0.1 --user admin \
        --password secret --threshold 0.005 --clear-counters
    python interface_error_monitor.py --host 10.0.0.1 --user admin \
        --interfaces Gi Te --device-type cisco_ios

Prerequisites:
    pip install netmiko
    SSH access to the target device.
    Privilege level 15 required only when --clear-counters is used.
"""

import argparse
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def parse_interfaces(output: str) -> list:
    """Return list of dicts with per-interface counter data from 'show interfaces'."""
    interfaces = []
    current = {}

    for line in output.splitlines():
        m = re.match(r'^(\S+)\s+is\s+(\S+),\s+line protocol is\s+(\S+)', line)
        if m:
            if current:
                interfaces.append(current)
            current = {
                "name": m.group(1),
                "admin": m.group(2),
                "proto": m.group(3).rstrip(","),
                "in_pkts": 0,
                "out_pkts": 0,
                "in_errors": 0,
                "out_errors": 0,
            }
            continue

        if not current:
            continue

        if re.search(r'\d+\s+packets input', line):
            current["in_pkts"] = int(re.search(r'(\d+)\s+packets input', line).group(1))
        if re.search(r'\d+\s+packets output', line):
            current["out_pkts"] = int(re.search(r'(\d+)\s+packets output', line).group(1))
        if re.search(r'\d+\s+input errors', line):
            current["in_errors"] = int(re.search(r'(\d+)\s+input errors', line).group(1))
        if re.search(r'\d+\s+output errors', line):
            current["out_errors"] = int(re.search(r'(\d+)\s+output errors', line).group(1))

    if current:
        interfaces.append(current)

    return interfaces


def error_rate(errors: int, packets: int) -> float:
    return errors / packets if packets else 0.0


def run(args) -> list:
    password = args.password or getpass(f"Password for {args.user}@{args.host}: ")

    device_params = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.user,
        "password": password,
        "timeout": 30,
    }

    try:
        log.info("Connecting to %s (%s)", args.host, args.device_type)
        with ConnectHandler(**device_params) as conn:
            log.info("Collecting interface counters")
            raw = conn.send_command("show interfaces", read_timeout=90)

        interfaces = parse_interfaces(raw)

        if args.interfaces:
            prefixes = tuple(p.lower() for p in args.interfaces)
            interfaces = [i for i in interfaces if i["name"].lower().startswith(prefixes)]

        flagged = []
        for intf in interfaces:
            in_rate = error_rate(intf["in_errors"], intf["in_pkts"])
            out_rate = error_rate(intf["out_errors"], intf["out_pkts"])
            if in_rate > args.threshold or out_rate > args.threshold:
                flagged.append({**intf, "in_rate": in_rate, "out_rate": out_rate})
                log.warning(
                    "%-40s  state=%-4s/%-4s  in_err=%.3f%%  out_err=%.3f%%",
                    intf["name"],
                    intf["admin"],
                    intf["proto"],
                    in_rate * 100,
                    out_rate * 100,
                )

        if not flagged:
            log.info(
                "All interfaces within threshold (%.3f%%)", args.threshold * 100
            )

        if args.clear_counters:
            with ConnectHandler(**device_params) as conn:
                log.info("Clearing counters on %s", args.host)
                conn.send_command_timing(
                    "clear counters", strip_prompt=False, strip_command=False
                )
                conn.send_command_timing("\n")
                log.info("Counters cleared")

    except NetmikoTimeoutException:
        log.error("Connection to %s timed out", args.host)
        sys.exit(1)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.user, args.host)
        sys.exit(1)

    return flagged


def main():
    parser = argparse.ArgumentParser(
        description="Flag network interfaces whose error rates exceed a threshold."
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument(
        "--device-type", default="cisco_ios",
        metavar="TYPE",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument(
        "--threshold", type=float, default=0.001,
        metavar="RATE",
        help="Error fraction threshold, e.g. 0.001 = 0.1%% (default: 0.001)",
    )
    parser.add_argument(
        "--clear-counters", action="store_true",
        help="Clear interface counters after reporting (requires privilege 15)",
    )
    parser.add_argument(
        "--interfaces", nargs="+", metavar="PREFIX",
        help="Restrict to interfaces starting with PREFIX, e.g. Gi Te Fa",
    )

    args = parser.parse_args()
    flagged = run(args)
    sys.exit(1 if flagged else 0)


if __name__ == "__main__":
    main()