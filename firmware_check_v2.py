Here is the script:

"""
neighbor_map.py - Collect and display CDP/LLDP neighbor topology from network devices.

Purpose:
    Connects to one or more Cisco/Arista devices via SSH and retrieves CDP or LLDP
    neighbor detail, producing a structured topology report. Useful for verifying
    physical cabling, auditing unexpected adjacencies, and building network diagrams.

Usage:
    python neighbor_map.py -d 192.168.1.1 -u admin -p secret
    python neighbor_map.py -d 192.168.1.1 -u admin --protocol lldp
    python neighbor_map.py --hosts hosts.txt -u admin --output json
    python neighbor_map.py -d 192.168.1.1 -u admin --device-type cisco_nxos

Prerequisites:
    pip install netmiko
"""

import argparse
import json
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

CDP_CMD = "show cdp neighbors detail"
LLDP_CMD = "show lldp neighbors detail"


def parse_cdp(output):
    neighbors = []
    for block in re.split(r"-{3,}", output):
        if not block.strip():
            continue
        n = {}
        m = re.search(r"Device ID:\s*(\S+)", block)
        if m:
            n["device_id"] = m.group(1)
        m = re.search(r"IP address:\s*(\S+)", block, re.IGNORECASE)
        if m:
            n["ip"] = m.group(1)
        m = re.search(r"Interface:\s*(\S+?),\s*Port ID.*?:\s*(\S+)", block)
        if m:
            n["local_port"] = m.group(1).rstrip(",")
            n["remote_port"] = m.group(2)
        m = re.search(r"Platform:\s*([^,\n]+)", block)
        if m:
            n["platform"] = m.group(1).strip()
        m = re.search(r"Software Version.*?:\s*(.+)", block)
        if m:
            n["version"] = m.group(1).strip()[:80]
        if n.get("device_id"):
            neighbors.append(n)
    return neighbors


def parse_lldp(output):
    neighbors = []
    for block in re.split(r"-{3,}", output):
        if not block.strip():
            continue
        n = {}
        m = re.search(r"System Name:\s*(\S+)", block)
        if m:
            n["device_id"] = m.group(1)
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", block)
        if m:
            n["ip"] = m.group(1)
        m = re.search(r"Local Port\s*(?:id)?:\s*(\S+)", block, re.IGNORECASE)
        if m:
            n["local_port"] = m.group(1)
        m = re.search(r"Port(?:\s+Description)?.*?:\s*(\S+)", block)
        if m:
            n["remote_port"] = m.group(1)
        m = re.search(r"System Description.*?:\n\s*(.+)", block)
        if m:
            n["platform"] = m.group(1).strip()[:80]
        if n.get("device_id"):
            neighbors.append(n)
    return neighbors


def collect(host, username, password, device_type, protocol, enable_secret=None):
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
    }
    if enable_secret:
        params["secret"] = enable_secret
    try:
        log.info("Connecting to %s", host)
        with ConnectHandler(**params) as conn:
            if enable_secret:
                conn.enable()
            cmd = CDP_CMD if protocol == "cdp" else LLDP_CMD
            raw = conn.send_command(cmd, read_timeout=60)
            if "% Invalid" in raw or "not enabled" in raw.lower():
                log.warning("%s: %s not available on this device", host, protocol.upper())
                return []
            return parse_cdp(raw) if protocol == "cdp" else parse_lldp(raw)
    except NetmikoAuthenticationException:
        log.error("Authentication failed: %s", host)
    except NetmikoTimeoutException:
        log.error("Connection timed out: %s", host)
    except Exception as exc:
        log.error("Error on %s: %s", host, exc)
    return None


def render_table(host, neighbors, protocol):
    bar = "=" * 72
    print(f"\n{bar}")
    print(f"  {host}  —  {len(neighbors)} neighbor(s) via {protocol.upper()}")
    print(bar)
    if not neighbors:
        print("  (none)")
        return
    hdr = "  {:<22} {:<16} {:<16} {:<16}"
    print(hdr.format("Neighbor ID", "IP", "Local Port", "Remote Port"))
    print("  " + "-" * 68)
    row = "  {:<22} {:<16} {:<16} {:<16}"
    for n in neighbors:
        print(row.format(
            n.get("device_id", "?")[:21],
            n.get("ip", "N/A")[:15],
            n.get("local_port", "?")[:15],
            n.get("remote_port", "?")[:15],
        ))


def build_args():
    p = argparse.ArgumentParser(
        description="Map CDP/LLDP neighbors on network devices.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--device", help="Single device IP or hostname")
    target.add_argument("--hosts", metavar="FILE", help="File listing one host per line")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument("-e", "--enable", dest="enable_secret", default=None,
                   help="Enable secret for privilege escalation")
    p.add_argument("--device-type", default="cisco_ios",
                   help="Netmiko device type string")
    p.add_argument("--protocol", choices=["cdp", "lldp"], default="cdp",
                   help="Neighbor discovery protocol")
    p.add_argument("--output", choices=["table", "json"], default="table")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args()


def load_hosts(args):
    if args.device:
        return [args.device]
    try:
        with open(args.hosts) as fh:
            return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    except OSError as exc:
        log.error("Cannot read hosts file: %s", exc)
        sys.exit(1)


def main():
    args = build_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass(f"SSH password for {args.username}: ")

    hosts = load_hosts(args)
    results = {}
    for host in hosts:
        neighbors = collect(host, args.username, password,
                            args.device_type, args.protocol, args.enable_secret)
        results[host] = neighbors if neighbors is not None else []
        if args.output == "table":
            if neighbors is not None:
                render_table(host, neighbors, args.protocol)
            else:
                print(f"\n[FAILED] {host}")

    if args.output == "json":
        print(json.dumps(results, indent=2))

    failed = [h for h, n in results.items() if n is None]
    if failed:
        log.warning("%d host(s) unreachable: %s", len(failed), ", ".join(failed))
        sys.exit(1)


if __name__ == "__main__":
    main()