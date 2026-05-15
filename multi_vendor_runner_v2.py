The user requested output-only with no explanation, so here is the script:

"""
interface_audit.py - Network interface inventory and error auditor.

Connects to one or more network devices, collects per-interface status and
error counters, and produces structured output (console table, CSV, or JSON)
suitable for capacity planning, change-window baselines, and post-incident
error analysis.

Usage:
    python interface_audit.py -d 192.168.1.1 -u admin -p secret
    python interface_audit.py --inventory devices.txt -u admin --csv report.csv
    python interface_audit.py -d 10.0.0.1 --device-type cisco_nxos --errors-only
    python interface_audit.py -d 10.0.0.1 -u admin --down-only --json down.json

Prerequisites:
    pip install netmiko

Supported device types: cisco_ios, cisco_nxos, cisco_xr, arista_eos
"""

import argparse
import csv
import getpass
import json
import logging
import re
import sys

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger(__name__)

SHOW_CMD = {
    "cisco_ios": "show interfaces",
    "cisco_nxos": "show interface",
    "cisco_xr": "show interfaces",
    "arista_eos": "show interfaces",
}

FIELDS = [
    "host", "interface", "link_status", "protocol_status",
    "description", "speed", "duplex",
    "input_errors", "crc_errors", "output_errors",
    "input_drops", "output_drops",
]


def _int(match, group=1):
    return int(match.group(group)) if match else 0


def parse_interfaces(raw: str) -> list:
    """Parse Cisco-style `show interfaces` output into a list of dicts."""
    records = []
    for block in re.split(r'(?=^\S)', raw, flags=re.MULTILINE):
        if not block.strip():
            continue

        header = re.match(
            r'^(\S+)\s+is\s+(up|down|administratively down)'
            r'[,\s]+line protocol is\s+(up|down)',
            block, re.IGNORECASE,
        )
        if not header:
            continue

        desc_m = re.search(r'Description:\s+(.+)', block)
        spd_m = re.search(r'(\d+\s?[MG]b/s|[Aa]uto|[Uu]nknown)', block)
        dup_m = re.search(r'(\w+-[Dd]uplex|\w+ [Dd]uplex)', block)
        in_err_m = re.search(r'(\d+) input errors', block)
        crc_m = re.search(r'(\d+) CRC', block)
        out_err_m = re.search(r'(\d+) output errors', block)
        in_drop_m = re.search(r'(\d+) ignored', block)
        out_drop_m = re.search(r'(\d+) output drops', block)

        records.append({
            "interface": header.group(1),
            "link_status": header.group(2).lower(),
            "protocol_status": header.group(3).lower(),
            "description": desc_m.group(1).strip() if desc_m else "",
            "speed": spd_m.group(1).strip() if spd_m else "",
            "duplex": dup_m.group(1).strip() if dup_m else "",
            "input_errors": _int(in_err_m),
            "crc_errors": _int(crc_m),
            "output_errors": _int(out_err_m),
            "input_drops": _int(in_drop_m),
            "output_drops": _int(out_drop_m),
        })

    return records


def audit_device(host: str, username: str, password: str, device_type: str,
                 port: int = 22, enable_secret: str = "") -> list:
    """SSH to a device, run show interfaces, return parsed records tagged with host."""
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
    }
    if enable_secret:
        params["secret"] = enable_secret

    log.info("Connecting to %s (%s)", host, device_type)
    try:
        with ConnectHandler(**params) as conn:
            if enable_secret:
                conn.enable()
            raw = conn.send_command(SHOW_CMD.get(device_type, "show interfaces"))
    except NetmikoAuthenticationException:
        log.error("Authentication failed: %s", host)
        return []
    except NetmikoTimeoutException:
        log.error("Connection timed out: %s", host)
        return []
    except Exception as exc:
        log.error("Error on %s: %s", host, exc)
        return []

    records = parse_interfaces(raw)
    for r in records:
        r["host"] = host
    log.info("  %d interfaces collected from %s", len(records), host)
    return records


def load_inventory(path: str) -> list:
    with open(path) as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def write_csv(records: list, path: str) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)
    log.info("CSV: %s (%d rows)", path, len(records))


def print_table(records: list, hosts: list) -> None:
    hdr = (
        f"{'HOST':<20} {'INTERFACE':<26} {'LINK':<8} {'PROTO':<8}"
        f" {'IN_ERR':>8} {'CRC':>6} {'OUT_ERR':>8}"
    )
    print(hdr)
    print("-" * len(hdr))
    for r in records:
        print(
            f"{r['host']:<20} {r['interface']:<26}"
            f" {r['link_status']:<8} {r['protocol_status']:<8}"
            f" {r['input_errors']:>8} {r['crc_errors']:>6} {r['output_errors']:>8}"
        )
    print(f"\n{len(records)} interface(s) across {len(hosts)} device(s)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Collect interface status and error counters from network devices."
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("-d", "--device", help="Single device IP or hostname")
    src.add_argument("--inventory", metavar="FILE", help="File with one host per line")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", default="", help="Password (prompted if omitted)")
    p.add_argument("--enable-secret", default="", metavar="SECRET")
    p.add_argument(
        "--device-type", default="cisco_ios", choices=list(SHOW_CMD),
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--errors-only", action="store_true",
                   help="Show only interfaces with non-zero error counters")
    p.add_argument("--down-only", action="store_true",
                   help="Show only interfaces where link or protocol is down")
    p.add_argument("--csv", metavar="FILE", help="Write output to CSV")
    p.add_argument("--json", metavar="FILE", help="Write output to JSON")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.password:
        args.password = getpass.getpass(f"Password for {args.username}: ")

    hosts = [args.device] if args.device else load_inventory(args.inventory)

    all_records = []
    for host in hosts:
        all_records.extend(audit_device(
            host=host,
            username=args.username,
            password=args.password,
            device_type=args.device_type,
            port=args.port,
            enable_secret=args.enable_secret,
        ))

    if args.errors_only:
        all_records = [
            r for r in all_records
            if r["input_errors"] or r["output_errors"] or r["crc_errors"]
        ]

    if args.down_only:
        all_records = [
            r for r in all_records
            if r["link_status"] != "up" or r["protocol_status"] != "up"
        ]

    if args.csv:
        write_csv(all_records, args.csv)

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(all_records, fh, indent=2)
        log.info("JSON: %s (%d records)", args.json, len(all_records))

    if not args.csv and not args.json:
        print_table(all_records, hosts)