The repo described in the prompt is the target portfolio repo, not this local directory. I'll write the script now — an interface error counter monitor, which is a concrete and distinct use of show-command parsing.

#!/usr/bin/env python3
"""
Interface Error Counter Monitor
=================================
Connects to a Cisco IOS/IOS-XE device via SSH and collects per-interface
error counters from 'show interfaces'. Flags any interface that exceeds
configurable thresholds for input errors, CRC errors, output errors, or
interface resets — the four counters most predictive of physical-layer faults.

Usage:
    python 030_show_command_parser.py -H 192.168.1.1 -u admin
    python 030_show_command_parser.py -H 192.168.1.1 -u admin -p secret \\
        --input-errors 50 --crc-errors 10 --json
    python 030_show_command_parser.py -H 192.168.1.1 -u admin --all --json

Prerequisites:
    pip install netmiko
    SSH reachability to target device
    User with at least privilege 1 (read-only show commands sufficient)

Exit codes:
    0  No interfaces exceeded thresholds
    1  One or more interfaces flagged, or connection failure
"""

import argparse
import json
import logging
import re
import sys
from getpass import getpass
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def parse_interface_errors(output: str) -> list[dict]:
    """Extract error counters from 'show interfaces' raw output."""
    interfaces = []

    blocks = re.split(r"\n(?=\S+\s+is\s+(?:up|down|administratively down))", output)

    intf_re = re.compile(r"^(\S+)\s+is\s+(up|down|administratively down)")
    in_err_re = re.compile(r"(\d+)\s+input errors,\s+(\d+)\s+CRC")
    out_err_re = re.compile(r"(\d+)\s+output errors")
    resets_re = re.compile(r"(\d+)\s+interface resets")

    for block in blocks:
        m = intf_re.match(block.strip())
        if not m:
            continue

        in_m = in_err_re.search(block)
        out_m = out_err_re.search(block)
        rst_m = resets_re.search(block)

        interfaces.append({
            "interface": m.group(1),
            "status": m.group(2),
            "input_errors": int(in_m.group(1)) if in_m else 0,
            "crc_errors": int(in_m.group(2)) if in_m else 0,
            "output_errors": int(out_m.group(1)) if out_m else 0,
            "resets": int(rst_m.group(1)) if rst_m else 0,
        })

    return interfaces


def flag_interfaces(
    interfaces: list[dict],
    input_errors: int,
    output_errors: int,
    crc_errors: int,
    resets: int,
) -> list[dict]:
    return [
        i for i in interfaces
        if (
            i["input_errors"] >= input_errors
            or i["output_errors"] >= output_errors
            or i["crc_errors"] >= crc_errors
            or i["resets"] >= resets
        )
    ]


def print_table(host: str, flagged: list[dict], total: int) -> None:
    print(f"\n{'='*70}")
    print(f"Interface Error Report  —  {host}")
    print(f"{'='*70}")
    print(f"Interfaces parsed : {total}")
    print(f"Interfaces flagged: {len(flagged)}")

    if not flagged:
        print("\nAll interfaces within thresholds.")
        return

    col = "{:<28} {:<26} {:>8} {:>6} {:>8} {:>7}"
    print()
    print(col.format("Interface", "Status", "In-Err", "CRC", "Out-Err", "Resets"))
    print("-" * 90)
    for i in flagged:
        print(col.format(
            i["interface"], i["status"],
            i["input_errors"], i["crc_errors"],
            i["output_errors"], i["resets"],
        ))


def connect_and_collect(args: argparse.Namespace) -> Optional[list[dict]]:
    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "timeout": args.timeout,
        "global_delay_factor": 2,
    }

    try:
        log.info("Connecting to %s:%d as %s", args.host, args.port, args.username)
        with ConnectHandler(**device) as conn:
            log.info("Connected — running 'show interfaces'")
            raw = conn.send_command("show interfaces", read_timeout=90)
        interfaces = parse_interface_errors(raw)
        log.info("Parsed %d interfaces", len(interfaces))
        return interfaces

    except NetmikoAuthenticationException:
        log.error("Authentication failed for '%s' on %s", args.username, args.host)
    except NetmikoTimeoutException:
        log.error("Timed out connecting to %s:%d", args.host, args.port)
    except Exception as exc:
        log.error("Unexpected error: %s", exc)

    return None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Flag Cisco interfaces with elevated error counters.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None,
                   help="SSH password (prompted if omitted)")
    p.add_argument("-t", "--device-type", default="cisco_ios",
                   help="Netmiko device type")
    p.add_argument("--port", type=int, default=22, help="SSH port")
    p.add_argument("--timeout", type=int, default=30,
                   help="Connection timeout in seconds")
    p.add_argument("--input-errors", type=int, default=10,
                   help="Threshold for input errors")
    p.add_argument("--output-errors", type=int, default=10,
                   help="Threshold for output errors")
    p.add_argument("--crc-errors", type=int, default=5,
                   help="Threshold for CRC errors")
    p.add_argument("--resets", type=int, default=5,
                   help="Threshold for interface resets")
    p.add_argument("--json", action="store_true",
                   help="Emit JSON instead of a formatted table")
    p.add_argument("--all", action="store_true",
                   help="Include all interfaces, not just flagged ones")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Enable debug logging")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.password is None:
        args.password = getpass(f"Password for {args.username}@{args.host}: ")

    interfaces = connect_and_collect(args)
    if interfaces is None:
        sys.exit(1)

    flagged = flag_interfaces(
        interfaces,
        input_errors=args.input_errors,
        output_errors=args.output_errors,
        crc_errors=args.crc_errors,
        resets=args.resets,
    )

    payload = interfaces if args.all else flagged

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print_table(args.host, flagged, len(interfaces))

    sys.exit(1 if flagged else 0)