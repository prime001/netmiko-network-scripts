```python
"""
interface_error_monitor.py

Parse interface error counters from a network device and alert when any
counter exceeds a configurable threshold.  Useful for proactive fault
detection and baseline-drift analysis without a full SNMP stack.

Usage:
    python interface_error_monitor.py -d 192.168.1.1 -u admin
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret \
        --crc-threshold 10 --input-errors-threshold 100 --output json
    python interface_error_monitor.py -d 192.168.1.1 -u admin --all \
        --output csv > errors.csv

Prerequisites:
    pip install netmiko
    Tested against Cisco IOS / IOS-XE.  Pass --device-type for other
    platforms (e.g. cisco_nxos, cisco_xr, juniper_junos).

Exit codes:
    0  No threshold violations
    1  Connection / auth error
    2  One or more interfaces exceed a threshold
"""

import argparse
import csv
import json
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

_IFACE_HEADER = re.compile(r"^(\S+) is (up|down|administratively down)")
_PATTERNS = {
    "input_errors": re.compile(r"(\d+) input errors"),
    "crc": re.compile(r"(\d+) CRC"),
    "runts": re.compile(r"(\d+) runts"),
    "giants": re.compile(r"(\d+) giants"),
    "output_drops": re.compile(r"(\d+) output drops"),
    "input_drops": re.compile(r"(\d+) input drops"),
}


def parse_interface_errors(raw):
    interfaces = []
    current = None
    for line in raw.splitlines():
        m = _IFACE_HEADER.match(line)
        if m:
            if current:
                interfaces.append(current)
            current = {
                "interface": m.group(1),
                "status": m.group(2),
                "input_errors": 0,
                "crc": 0,
                "runts": 0,
                "giants": 0,
                "output_drops": 0,
                "input_drops": 0,
            }
            continue
        if current is None:
            continue
        for key, pattern in _PATTERNS.items():
            hit = pattern.search(line)
            if hit:
                current[key] = int(hit.group(1))
    if current:
        interfaces.append(current)
    return interfaces


def check_thresholds(interfaces, thresholds):
    violations = []
    for iface in interfaces:
        exceeded = {k: iface[k] for k, limit in thresholds.items() if iface.get(k, 0) > limit}
        if exceeded:
            violations.append({**iface, "violations": list(exceeded.keys())})
    return violations


def connect_and_collect(host, username, password, device_type, port, secret):
    params = {"device_type": device_type, "host": host, "username": username,
              "password": password, "port": port}
    if secret:
        params["secret"] = secret
    logger.info("Connecting to %s", host)
    with ConnectHandler(**params) as conn:
        if secret:
            conn.enable()
        return conn.send_command("show interfaces", read_timeout=60)


def print_text(rows, show_violations_marker=True):
    if not rows:
        print("No interfaces match criteria.")
        return
    w = max(len(r["interface"]) for r in rows)
    hdr = f"{'Interface':<{w}}  {'Status':<25}  {'CRC':>6}  {'InErr':>7}  {'Runts':>6}  {'Giants':>7}  {'OutDrop':>8}"
    if show_violations_marker:
        hdr += "  Violations"
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        line = (f"{r['interface']:<{w}}  {r['status']:<25}  {r['crc']:>6}  "
                f"{r['input_errors']:>7}  {r['runts']:>6}  {r['giants']:>7}  "
                f"{r['output_drops']:>8}")
        if show_violations_marker and "violations" in r:
            line += f"  {','.join(r['violations'])}"
        print(line)


def print_csv(rows):
    fields = ["interface", "status", "crc", "input_errors", "runts", "giants",
              "output_drops", "input_drops"]
    writer = csv.DictWriter(sys.stdout, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)


def build_parser():
    p = argparse.ArgumentParser(description="Report interface error counter violations.")
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    p.add_argument("--secret", help="Enable secret")
    p.add_argument("--device-type", default="cisco_ios",
                   help="Netmiko device type (default: cisco_ios)")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--crc-threshold", type=int, default=0, metavar="N")
    p.add_argument("--input-errors-threshold", type=int, default=0, metavar="N")
    p.add_argument("--output-drops-threshold", type=int, default=0, metavar="N")
    p.add_argument("--runts-threshold", type=int, default=0, metavar="N")
    p.add_argument("--giants-threshold", type=int, default=0, metavar="N")
    p.add_argument("--all", action="store_true",
                   help="Show all interfaces, not just violations")
    p.add_argument("--output", choices=["text", "json", "csv"], default="text")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}@{args.device}: ")

    thresholds = {
        "crc": args.crc_threshold,
        "input_errors": args.input_errors_threshold,
        "output_drops": args.output_drops_threshold,
        "runts": args.runts_threshold,
        "giants": args.giants_threshold,
    }

    try:
        raw = connect_and_collect(
            args.device, args.username, password,
            args.device_type, args.port, args.secret,
        )
    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        logger.error("Connection timed out to %s", args.device)
        sys.exit(1)
    except Exception as exc:
        logger.error("Connection error: %s", exc)
        sys.exit(1)

    interfaces = parse_interface_errors(raw)
    violations = check_thresholds(interfaces, thresholds)
    display = interfaces if args.all else violations

    if args.output == "json":
        print(json.dumps(display, indent=2))
    elif args.output == "csv":
        print_csv(display)
    else:
        print_text(display, show_violations_marker=not args.all)

    sys.exit(2 if violations else 0)
```