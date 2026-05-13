```python
"""
lldp_cdp_mapper.py - Network topology discovery via LLDP/CDP neighbor crawling.

Purpose:
    Connects to a seed device and discovers adjacent devices by parsing LLDP/CDP
    neighbor tables. Optionally performs a multi-hop BFS crawl to build a topology
    map and exports results as a human-readable adjacency table or JSON file.

Usage:
    python lldp_cdp_mapper.py --host 10.0.0.1 -u admin -p secret
    python lldp_cdp_mapper.py --host 10.0.0.1 -u admin -p secret --depth 3 --protocol lldp
    python lldp_cdp_mapper.py --host 10.0.0.1 -u admin -p secret --json-out topology.json

Prerequisites:
    pip install netmiko
    Device must have CDP or LLDP enabled; user requires at minimum read-only access.
    Multi-hop crawl requires reachability and credentials on each discovered neighbor.
"""

import argparse
import json
import logging
import re
import sys
from collections import defaultdict
from getpass import getpass

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

SUPPORTED_DEVICE_TYPES = [
    "cisco_ios", "cisco_xe", "cisco_nxos", "cisco_xr", "arista_eos",
]


def parse_cdp_neighbors(output):
    neighbors = []
    for block in re.split(r"-{10,}", output):
        if not block.strip():
            continue
        entry = {}
        m = re.search(r"Device ID:\s*(\S+)", block)
        if m:
            entry["device_id"] = m.group(1)
        m = re.search(r"IP(?:v4)? address:\s*(\d[\d.]+)", block, re.IGNORECASE)
        if m:
            entry["mgmt_ip"] = m.group(1)
        m = re.search(r"Platform:\s*([^,\n]+)", block)
        if m:
            entry["platform"] = m.group(1).strip()
        m = re.search(r"Interface:\s*(\S+),\s*Port ID[^:]*:\s*(\S+)", block)
        if m:
            entry["local_port"] = m.group(1).rstrip(",")
            entry["remote_port"] = m.group(2)
        if entry.get("device_id"):
            neighbors.append(entry)
    return neighbors


def parse_lldp_neighbors(output):
    neighbors = []
    for block in re.split(r"(?=Local\s+Intf)", output, flags=re.IGNORECASE):
        if not block.strip():
            continue
        entry = {}
        m = re.search(r"System Name:\s*(\S+)", block, re.IGNORECASE)
        if m:
            entry["device_id"] = m.group(1)
        m = re.search(r"(?:Management Address|IP[v4]*).*?(\d{1,3}(?:\.\d{1,3}){3})",
                      block, re.IGNORECASE | re.DOTALL)
        if m:
            entry["mgmt_ip"] = m.group(1)
        m = re.search(r"System Description:\s*(.+)", block)
        if m:
            entry["platform"] = m.group(1).strip()[:60]
        m = re.search(r"Local\s+Intf[a-z]*:\s*(\S+)", block, re.IGNORECASE)
        if m:
            entry["local_port"] = m.group(1)
        m = re.search(r"Port\s+(?:id|ID):\s*(\S+)", block)
        if m:
            entry["remote_port"] = m.group(1)
        if entry.get("device_id"):
            neighbors.append(entry)
    return neighbors


def query_device(host, username, password, device_type, protocol):
    device_params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "timeout": 20,
        "session_log": None,
    }
    try:
        log.info("Connecting to %s", host)
        with ConnectHandler(**device_params) as conn:
            if protocol == "cdp":
                output = conn.send_command("show cdp neighbors detail", read_timeout=30)
                return parse_cdp_neighbors(output)
            output = conn.send_command("show lldp neighbors detail", read_timeout=30)
            return parse_lldp_neighbors(output)
    except NetmikoAuthenticationException:
        log.error("Authentication failed: %s", host)
    except NetmikoTimeoutException:
        log.error("Timeout: %s", host)
    except Exception as exc:
        log.error("Error on %s: %s", host, exc)
    return None


def crawl_topology(seed, username, password, device_type, protocol, max_depth):
    adjacency = defaultdict(list)
    visited = set()
    queue = [(seed, 0)]

    while queue:
        host, depth = queue.pop(0)
        if host in visited:
            continue
        visited.add(host)

        neighbors = query_device(host, username, password, device_type, protocol)
        if neighbors is None:
            log.warning("Skipped %s (connection failed)", host)
            continue

        adjacency[host] = neighbors
        log.info("  %s: %d neighbor(s) found", host, len(neighbors))

        if depth < max_depth:
            for nbr in neighbors:
                nbr_ip = nbr.get("mgmt_ip")
                if nbr_ip and nbr_ip not in visited:
                    queue.append((nbr_ip, depth + 1))

    return dict(adjacency)


def print_table(adjacency):
    col = "{:<22} {:<16} {:<24} {:<18} {:<16}"
    header = col.format("Local Device", "Neighbor IP", "Neighbor ID", "Local Port", "Remote Port")
    separator = "-" * len(header)
    print(separator)
    print(header)
    print(separator)
    for device, neighbors in sorted(adjacency.items()):
        if not neighbors:
            print(col.format(device, "-", "(no neighbors found)", "-", "-"))
            continue
        for nbr in neighbors:
            print(col.format(
                device,
                nbr.get("mgmt_ip", "unknown"),
                nbr.get("device_id", "unknown"),
                nbr.get("local_port", "-"),
                nbr.get("remote_port", "-"),
            ))
    print(separator)
    total_links = sum(len(v) for v in adjacency.values())
    print(f"Devices crawled: {len(adjacency)}  |  Total adjacencies: {total_links}")


def main():
    parser = argparse.ArgumentParser(
        description="Map network topology by crawling CDP/LLDP neighbor tables",
    )
    parser.add_argument("--host", required=True, help="Seed device IP or hostname")
    parser.add_argument("--username", "-u", required=True, help="SSH username")
    parser.add_argument("--password", "-p", default=None,
                        help="SSH password (will prompt if omitted)")
    parser.add_argument("--device-type", default="cisco_ios",
                        choices=SUPPORTED_DEVICE_TYPES,
                        help="Netmiko device type (default: cisco_ios)")
    parser.add_argument("--protocol", choices=["cdp", "lldp"], default="cdp",
                        help="Neighbor discovery protocol (default: cdp)")
    parser.add_argument("--depth", type=int, default=1, metavar="N",
                        help="Crawl hops from seed: 1=seed only, 2=+one hop (default: 1)")
    parser.add_argument("--json-out", metavar="FILE",
                        help="Write full topology to JSON file")
    parser.add_argument("--debug", action="store_true",
                        help="Enable verbose debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.depth < 1:
        parser.error("--depth must be >= 1")

    password = args.password or getpass(f"Password for {args.username}@{args.host}: ")

    topology = crawl_topology(
        args.host, args.username, password,
        args.device_type, args.protocol, args.depth,
    )

    if not topology:
        log.error("No topology data collected — verify connectivity and credentials")
        sys.exit(1)

    print_table(topology)

    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(topology, fh, indent=2)
        log.info("Topology written to %s", args.json_out)


if __name__ == "__main__":
    main()
```