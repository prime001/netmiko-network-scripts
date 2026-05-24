cdp_lldp_mapper.py - Network topology discovery via CDP/LLDP neighbor tables

Purpose:
    Connects to a seed device and maps the reachable network topology by
    walking CDP (Cisco Discovery Protocol) or LLDP neighbor tables. Supports
    recursive multi-hop discovery via breadth-first traversal, producing a
    human-readable topology tree and optional JSON export.

Usage:
    python cdp_lldp_mapper.py -d 192.168.1.1 -u admin -p secret
    python cdp_lldp_mapper.py -d 192.168.1.1 -u admin -p secret --depth 3 --output topo.json
    python cdp_lldp_mapper.py -d 192.168.1.1 -u admin -p secret --protocol lldp

Prerequisites:
    pip install netmiko
    CDP or LLDP must be enabled on target devices.
    SSH access with valid credentials required on all discovered devices.
"""

import argparse
import json
import logging
import re
import sys
from collections import deque

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def parse_cdp_neighbors(output):
    neighbors = []
    for block in re.split(r"-{5,}", output):
        entry = {}
        m = re.search(r"Device ID:\s*(\S+)", block)
        if m:
            entry["device_id"] = m.group(1)
        m = re.search(r"IP address:\s*(\d+\.\d+\.\d+\.\d+)", block)
        if m:
            entry["ip"] = m.group(1)
        m = re.search(r"Platform:\s*([^,]+)", block)
        if m:
            entry["platform"] = m.group(1).strip()
        m = re.search(r"Interface:\s*(\S+),\s*Port ID.*?:\s*(\S+)", block)
        if m:
            entry["local_intf"] = m.group(1)
            entry["remote_intf"] = m.group(2)
        if entry.get("device_id") and entry.get("ip"):
            neighbors.append(entry)
    return neighbors


def parse_lldp_neighbors(output):
    neighbors = []
    for block in re.split(r"-{5,}", output):
        entry = {}
        m = re.search(r"System Name:\s*(\S+)", block)
        if m:
            entry["device_id"] = m.group(1)
        m = re.search(r"Management Addresses.*?IP:\s*(\d+\.\d+\.\d+\.\d+)", block, re.DOTALL)
        if not m:
            m = re.search(r"IP:\s*(\d+\.\d+\.\d+\.\d+)", block)
        if m:
            entry["ip"] = m.group(1)
        m = re.search(r"System Description:\s*(.+?)(?:\n|$)", block)
        if m:
            entry["platform"] = m.group(1).strip()
        m = re.search(r"Local Intf:\s*(\S+)", block)
        if m:
            entry["local_intf"] = m.group(1)
        m = re.search(r"Port id:\s*(\S+)", block)
        if m:
            entry["remote_intf"] = m.group(1)
        if entry.get("device_id") and entry.get("ip"):
            neighbors.append(entry)
    return neighbors


def get_neighbors(host, username, password, device_type, protocol, secret=""):
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "secret": secret,
        "timeout": 15,
    }
    try:
        with ConnectHandler(**params) as conn:
            if secret:
                conn.enable()
            if protocol == "cdp":
                output = conn.send_command("show cdp neighbors detail")
                return parse_cdp_neighbors(output)
            else:
                output = conn.send_command("show lldp neighbors detail")
                return parse_lldp_neighbors(output)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", host)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", host)
    except Exception as exc:
        log.error("Error on %s: %s", host, exc)
    return []


def discover_topology(seed_host, username, password, device_type, protocol, max_depth, secret=""):
    topology = {}
    visited = set()
    queue = deque([(seed_host, 0)])

    while queue:
        host, depth = queue.popleft()
        if host in visited or depth > max_depth:
            continue
        visited.add(host)
        log.info("Probing %s (depth %d)", host, depth)
        neighbors = get_neighbors(host, username, password, device_type, protocol, secret)
        topology[host] = neighbors
        if depth < max_depth:
            for n in neighbors:
                ip = n.get("ip")
                if ip and ip not in visited:
                    queue.append((ip, depth + 1))

    return topology


def print_topology(topology):
    for device, neighbors in topology.items():
        print(f"\n{device}")
        if not neighbors:
            print("  (no neighbors discovered)")
            continue
        for n in neighbors:
            print(
                f"  -> {n.get('device_id', 'unknown')} [{n.get('ip', '?')}]"
                f"  {n.get('local_intf', '?')} <-> {n.get('remote_intf', '?')}"
                f"  {n.get('platform', '')}"
            )


def main():
    parser = argparse.ArgumentParser(
        description="Map network topology via CDP/LLDP neighbor tables"
    )
    parser.add_argument("-d", "--device", required=True, help="Seed device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("-s", "--secret", default="", help="Enable secret")
    parser.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument(
        "--protocol", choices=["cdp", "lldp"], default="cdp",
        help="Neighbor discovery protocol (default: cdp)",
    )
    parser.add_argument(
        "--depth", type=int, default=1,
        help="Maximum hop depth for recursive discovery (default: 1)",
    )
    parser.add_argument("--output", help="Write topology JSON to this file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    topology = discover_topology(
        seed_host=args.device,
        username=args.username,
        password=args.password,
        device_type=args.device_type,
        protocol=args.protocol,
        max_depth=args.depth,
        secret=args.secret,
    )

    if not topology:
        log.error("No topology data collected")
        sys.exit(1)

    print_topology(topology)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(topology, f, indent=2)
        log.info("Topology written to %s", args.output)


if __name__ == "__main__":
    main()