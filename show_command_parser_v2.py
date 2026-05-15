```python
"""
neighbor_mapper.py — CDP/LLDP Neighbor Table Extractor

Connects to a Cisco IOS/IOS-XE device via Netmiko, retrieves CDP or LLDP
neighbor detail output, and parses it into a structured neighbor table.
Useful for topology documentation, cabling verification, and infrastructure
audits without requiring a full NMS.

Usage:
    python neighbor_mapper.py -H 10.0.0.1 -u admin -p secret
    python neighbor_mapper.py -H 10.0.0.1 -u admin -p secret --protocol lldp
    python neighbor_mapper.py -H 10.0.0.1 -u admin -p secret --format json
    python neighbor_mapper.py -H 10.0.0.1 -u admin -p secret --format csv -o neighbors.csv

Prerequisites:
    pip install netmiko
    CDP or LLDP must be enabled on the device.
    Account requires at minimum privilege level 1.
"""

import argparse
import csv
import json
import logging
import re
import sys

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.WARNING)
logger = logging.getLogger(__name__)

COLS = ["local_port", "device_id", "remote_port", "mgmt_ip", "platform", "capabilities"]
HEADERS = ["Local Port", "Device ID", "Remote Port", "Mgmt IP", "Platform", "Capabilities"]


def parse_cdp(raw: str) -> list[dict]:
    neighbors = []
    for block in re.split(r"-{5,}", raw):
        if not block.strip():
            continue
        n = {}
        m = re.search(r"Device ID:\s*(\S+)", block)
        if m:
            n["device_id"] = m.group(1)
        m = re.search(r"IP(?:v4)? [Aa]ddress:\s*(\S+)", block)
        if m:
            n["mgmt_ip"] = m.group(1)
        m = re.search(r"Platform:\s*([^,\n]+)", block)
        if m:
            n["platform"] = m.group(1).strip()
        m = re.search(r"Interface:\s*(\S+?)(?:,|$).*?Port ID.*?:\s*(\S+)", block, re.DOTALL)
        if m:
            n["local_port"] = m.group(1).rstrip(",")
            n["remote_port"] = m.group(2)
        m = re.search(r"Capabilities:\s*(.+)", block)
        if m:
            n["capabilities"] = m.group(1).strip()
        if n.get("device_id"):
            neighbors.append(n)
    return neighbors


def parse_lldp(raw: str) -> list[dict]:
    neighbors = []
    for block in re.split(r"-{5,}", raw):
        if not block.strip():
            continue
        n = {}
        m = re.search(r"System Name:\s*(\S+)", block)
        if m:
            n["device_id"] = m.group(1)
        m = re.search(r"IP(?:v4)?:\s*(\S+)", block)
        if m:
            n["mgmt_ip"] = m.group(1)
        m = re.search(r"System Description[^:]*:\s*\n\s*(.+)", block)
        if m:
            n["platform"] = m.group(1).strip()
        m = re.search(r"Local Intf(?:erface)?:\s*(\S+)", block)
        if m:
            n["local_port"] = m.group(1)
        m = re.search(r"Port (?:id|ID):\s*(\S+)", block)
        if m:
            n["remote_port"] = m.group(1)
        m = re.search(r"System Capabilit\w+:\s*(.+)", block)
        if m:
            n["capabilities"] = m.group(1).strip()
        if n.get("device_id"):
            neighbors.append(n)
    return neighbors


def render_table(neighbors: list[dict]) -> None:
    if not neighbors:
        print("No neighbors found.")
        return
    widths = [
        max(len(h), max((len(str(n.get(c, ""))) for n in neighbors), default=0))
        for h, c in zip(HEADERS, COLS)
    ]
    sep = "  ".join("-" * w for w in widths)
    row_fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(row_fmt.format(*HEADERS))
    print(sep)
    for n in neighbors:
        print(row_fmt.format(*[str(n.get(c, "")) for c in COLS]))


def render_json(neighbors: list[dict]) -> None:
    print(json.dumps(neighbors, indent=2))


def render_csv(neighbors: list[dict], outfile: str | None) -> None:
    dest = open(outfile, "w", newline="") if outfile else sys.stdout
    try:
        writer = csv.DictWriter(dest, fieldnames=COLS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(neighbors)
    finally:
        if outfile:
            dest.close()
            print(f"Saved {len(neighbors)} neighbor(s) to {outfile}")


def build_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Extract CDP/LLDP neighbor tables from Cisco devices.")
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)
    p.add_argument("--secret", default="", help="Enable secret (if required)")
    p.add_argument("--device-type", default="cisco_ios", help="Netmiko device type")
    p.add_argument("--protocol", choices=["cdp", "lldp"], default="cdp")
    p.add_argument("--format", choices=["table", "json", "csv"], default="table")
    p.add_argument("-o", "--output", metavar="FILE", help="Output file (CSV only)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args()


def main() -> int:
    args = build_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    conn_params = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "secret": args.secret,
    }
    command = f"show {args.protocol} neighbors detail"

    try:
        logger.info("Connecting to %s", args.host)
        with ConnectHandler(**conn_params) as conn:
            if args.secret:
                conn.enable()
            raw = conn.send_command(command)
    except NetmikoAuthenticationException:
        print(f"ERROR: Authentication failed for {args.host}", file=sys.stderr)
        return 1
    except NetmikoTimeoutException:
        print(f"ERROR: Connection timed out to {args.host}", file=sys.stderr)
        return 1

    parse = parse_cdp if args.protocol == "cdp" else parse_lldp
    neighbors = parse(raw)
    logger.info("Parsed %d neighbor(s)", len(neighbors))

    if args.format == "json":
        render_json(neighbors)
    elif args.format == "csv":
        render_csv(neighbors, args.output)
    else:
        print(f"\n{args.protocol.upper()} neighbors on {args.host}:\n")
        render_table(neighbors)

    return 0


if __name__ == "__main__":
    sys.exit(main())
```