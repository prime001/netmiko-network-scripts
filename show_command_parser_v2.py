#!/usr/bin/env python3
"""
interface_error_audit.py - Network interface error counter auditor.

Connects to a network device via SSH and audits all interfaces for input/output
errors, CRC errors, and dropped packets. Interfaces exceeding configurable
thresholds are flagged, making this useful for catching duplex mismatches,
faulty cables, and congested links before they cause outages.

Usage:
    python interface_error_audit.py -H 192.168.1.1 -u admin -p secret
    python interface_error_audit.py -H 192.168.1.1 -u admin \\
        --device-type cisco_nxos --error-threshold 100 --output report.csv

Prerequisites:
    pip install netmiko
"""

import argparse
import csv
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

SHOW_CMD = {
    "cisco_ios": "show interfaces",
    "cisco_xe": "show interfaces",
    "cisco_nxos": "show interface",
    "cisco_xr": "show interfaces",
}

_INTF_RE = re.compile(r"^(\S+) is (?:up|down|administratively down)", re.MULTILINE)
_IN_ERR_RE = re.compile(r"(\d+) input errors")
_OUT_ERR_RE = re.compile(r"(\d+) output errors")
_CRC_RE = re.compile(r"(\d+) CRC")
_IN_DROP_RE = re.compile(r"(\d+) input drops|(\d+) no buffer")
_OUT_DROP_RE = re.compile(r"(\d+) output drops")


def _counter(pattern, text):
    m = pattern.search(text)
    if not m:
        return 0
    return int(next(g for g in m.groups() if g is not None))


def parse_interfaces(raw_output, error_threshold, drop_threshold):
    blocks, current_name, current_lines = [], None, []

    for line in raw_output.splitlines():
        if _INTF_RE.match(line):
            if current_name:
                blocks.append((current_name, "\n".join(current_lines)))
            current_name = _INTF_RE.match(line).group(1)
            current_lines = [line]
        elif current_name:
            current_lines.append(line)

    if current_name:
        blocks.append((current_name, "\n".join(current_lines)))

    results = []
    for name, block in blocks:
        in_err = _counter(_IN_ERR_RE, block)
        out_err = _counter(_OUT_ERR_RE, block)
        crc = _counter(_CRC_RE, block)
        in_drop = _counter(_IN_DROP_RE, block)
        out_drop = _counter(_OUT_DROP_RE, block)
        flagged = (in_err + out_err) >= error_threshold or (in_drop + out_drop) >= drop_threshold
        results.append({
            "interface": name,
            "input_errors": in_err,
            "output_errors": out_err,
            "crc_errors": crc,
            "input_drops": in_drop,
            "output_drops": out_drop,
            "flagged": flagged,
        })

    return results


def print_report(host, results, error_threshold, drop_threshold):
    flagged = [r for r in results if r["flagged"]]
    print(f"\n{'='*72}")
    print(f"Interface Error Audit — {host}")
    print(f"Thresholds: errors>={error_threshold}, drops>={drop_threshold}")
    print(f"Interfaces scanned: {len(results)}   Flagged: {len(flagged)}")
    print(f"{'='*72}")
    if not flagged:
        print("  All interfaces within thresholds.\n")
        return
    print(f"{'Interface':<28} {'In Err':>8} {'Out Err':>8} {'CRC':>6} {'In Drop':>9} {'Out Drop':>10}")
    print("-" * 72)
    for r in flagged:
        print(
            f"{r['interface']:<28} {r['input_errors']:>8} {r['output_errors']:>8} "
            f"{r['crc_errors']:>6} {r['input_drops']:>9} {r['output_drops']:>10}"
        )
    print()


def write_csv(path, host, results):
    fields = ["host", "interface", "input_errors", "output_errors",
              "crc_errors", "input_drops", "output_drops", "flagged"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow({"host": host, **r})
    log.info("CSV report written to %s", path)


def parse_args():
    p = argparse.ArgumentParser(
        description="Audit interface error counters on network devices.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None,
                   help="SSH password (prompted if omitted)")
    p.add_argument("-t", "--device-type", default="cisco_ios",
                   choices=list(SHOW_CMD.keys()), help="Netmiko device type")
    p.add_argument("--error-threshold", type=int, default=10,
                   help="Flag when input+output errors >= N")
    p.add_argument("--drop-threshold", type=int, default=50,
                   help="Flag when input+output drops >= N")
    p.add_argument("--port", type=int, default=22, help="SSH port")
    p.add_argument("--timeout", type=int, default=30,
                   help="Connection timeout in seconds")
    p.add_argument("--output", metavar="FILE",
                   help="Write full results to CSV FILE")
    return p.parse_args()


def main():
    args = parse_args()
    password = args.password or getpass(f"Password for {args.username}@{args.host}: ")

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": password,
        "port": args.port,
        "timeout": args.timeout,
    }

    try:
        log.info("Connecting to %s (%s)", args.host, args.device_type)
        with ConnectHandler(**device) as conn:
            cmd = SHOW_CMD[args.device_type]
            log.info("Running '%s'", cmd)
            raw = conn.send_command(cmd, read_timeout=90)
    except AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        sys.exit(1)

    results = parse_interfaces(raw, args.error_threshold, args.drop_threshold)
    if not results:
        log.error("No interfaces parsed — verify device type and reachability.")
        sys.exit(2)

    print_report(args.host, results, args.error_threshold, args.drop_threshold)

    if args.output:
        write_csv(args.output, args.host, results)

    sys.exit(1 if any(r["flagged"] for r in results) else 0)


if __name__ == "__main__":
    main()