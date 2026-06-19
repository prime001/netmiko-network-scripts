cdp_lldp_mapper.py - Network topology discovery via CDP/LLDP neighbor walking

Purpose:
    Starting from a seed device, recursively discover network topology by
    collecting CDP and LLDP neighbor tables. Builds a hop-by-hop neighbor map
    that can be printed in human-readable form or exported as JSON.

Usage:
    python cdp_lldp_mapper.py --host 192.168.1.1 --username admin --password secret
    python cdp_lldp_mapper.py --host 10.0.0.1 -u admin --ask-pass --depth 3
    python cdp_lldp_mapper.py --host 10.0.0.1 -u admin -p secret --protocol lldp --output topo.json

Prerequisites:
    pip install netmiko
    CDP or LLDP must be enabled on target devices.
    SSH credentials require at minimum privilege-1 (show commands only).
"""

import argparse
import getpass
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


def get_device_hostname(connection):
    try:
        output = connection.send_command("show version", use_textfsm=False)
        match = re.search(r"^(\S+)\s+uptime", output, re.MULTILINE)
        if match:
            return match.group(1)
    except Exception:
        pass
    return connection.host


def collect_cdp_neighbors(connection):
    neighbors = []
    try:
        output = connection.send_command("show cdp neighbors detail")
    except Exception as exc:
        log.warning("CDP query failed on %s: %s", connection.host, exc)
        return neighbors

    for block in re.split(r"-{5,}", output):
        entry = {"protocol": "cdp"}
        m = re.search(r"Device ID:\s*(\S+)", block)
        if m:
            entry["device_id"] = m.group(1)
        m = re.search(r"IP address:\s*(\S+)", block, re.IGNORECASE)
        if m:
            entry["mgmt_ip"] = m.group(1)
        m = re.search(r"Platform:\s*([^,\n]+)", block)
        if m:
            entry["platform"] = m.group(1).strip()
        m = re.search(r"Interface:\s*(\S+),\s*Port ID.*?:\s*(\S+)", block)
        if m:
            entry["local_intf"] = m.group(1).rstrip(",")
            entry["remote_intf"] = m.group(2)
        if entry.get("device_id") and entry.get("mgmt_ip"):
            neighbors.append(entry)
    return neighbors


def collect_lldp_neighbors(connection):
    neighbors = []
    try:
        output = connection.send_command("show lldp neighbors detail")
    except Exception as exc:
        log.warning("LLDP query failed on %s: %s", connection.host, exc)
        return neighbors

    for block in re.split(r"-{5,}", output):
        entry = {"protocol": "lldp"}
        m = re.search(r"System Name:\s*(\S+)", block)
        if m:
            entry["device_id"] = m.group(1)
        m = re.search(r"Management Addresses.*?IP:\s*(\d[\d.]+)", block, re.DOTALL)
        if m:
            entry["mgmt_ip"] = m.group(1)
        m = re.search(r"Local Intf:\s*(\S+)", block)
        if m:
            entry["local_intf"] = m.group(1)
        m = re.search(r"Port id:\s*(\S+)", block)
        if m:
            entry["remote_intf"] = m.group(1)
        if entry.get("device_id") and entry.get("mgmt_ip"):
            neighbors.append(entry)
    return neighbors


def open_connection(host, username, password, device_type):
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "timeout": 15,
    }
    try:
        conn = ConnectHandler(**params)
        log.info("Connected to %s", host)
        return conn
    except NetmikoAuthenticationException:
        log.error("Authentication failed: %s", host)
    except NetmikoTimeoutException:
        log.error("Timeout: %s", host)
    except Exception as exc:
        log.error("Connection error %s: %s", host, exc)
    return None


def walk_topology(seed_host, username, password, device_type, protocol, max_depth):
    topology = {}
    visited = set()
    queue = deque([(seed_host, 0)])

    while queue:
        host, depth = queue.popleft()
        if host in visited or depth > max_depth:
            continue
        visited.add(host)

        conn = open_connection(host, username, password, device_type)
        if not conn:
            topology[host] = {"error": "connection_failed", "neighbors": [], "depth": depth}
            continue

        try:
            hostname = get_device_hostname(conn)
            neighbors = []
            if protocol in ("cdp", "both"):
                neighbors.extend(collect_cdp_neighbors(conn))
            if protocol in ("lldp", "both"):
                neighbors.extend(collect_lldp_neighbors(conn))

            topology[host] = {"hostname": hostname, "neighbors": neighbors, "depth": depth}
            log.info("  %s: %d neighbor(s)", hostname, len(neighbors))

            if depth < max_depth:
                for nbr in neighbors:
                    nbr_ip = nbr.get("mgmt_ip")
                    if nbr_ip and nbr_ip not in visited:
                        queue.append((nbr_ip, depth + 1))
        finally:
            conn.disconnect()

    return topology


def print_topology(topology):
    for host, data in sorted(topology.items(), key=lambda x: x[1].get("depth", 99)):
        if "error" in data:
            print(f"\n[{host}] ERROR: {data['error']}")
            continue
        print(f"\n[{host}] hostname={data.get('hostname','?')}  depth={data['depth']}")
        for nbr in data.get("neighbors", []):
            print(
                f"  {nbr.get('local_intf','?'):20s} -> "
                f"{nbr.get('device_id','?'):30s}  "
                f"[{nbr.get('mgmt_ip','?'):16s}]  "
                f"{nbr.get('remote_intf','?'):20s}  "
                f"({nbr.get('protocol','?')})"
            )


def main():
    parser = argparse.ArgumentParser(
        description="Discover network topology by walking CDP/LLDP neighbor tables"
    )
    parser.add_argument("--host", required=True, help="Seed device IP or hostname")
    parser.add_argument("--username", "-u", required=True, help="SSH username")
    parser.add_argument("--password", "-p", default=None, help="SSH password")
    parser.add_argument("--ask-pass", action="store_true", help="Prompt for password")
    parser.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)"
    )
    parser.add_argument(
        "--protocol", choices=["cdp", "lldp", "both"], default="cdp",
        help="Neighbor discovery protocol (default: cdp)"
    )
    parser.add_argument(
        "--depth", type=int, default=2,
        help="Maximum hop depth for recursive walk (default: 2, 0=seed only)"
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help="Write topology to this JSON file"
    )
    args = parser.parse_args()

    password = args.password
    if args.ask_pass or not password:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    log.info("Topology walk: seed=%s protocol=%s max_depth=%d", args.host, args.protocol, args.depth)
    topology = walk_topology(args.host, args.username, password, args.device_type, args.protocol, args.depth)

    print_topology(topology)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(topology, fh, indent=2)
        log.info("Topology written to %s", args.output)

    errors = sum(1 for d in topology.values() if "error" in d)
    log.info("Done: %d device(s) visited, %d error(s)", len(topology), errors)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())