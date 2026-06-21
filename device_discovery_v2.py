```python
"""
cdp_lldp_crawler.py - Network topology discovery via CDP/LLDP neighbor walking.

Purpose:
    Starting from a seed device, recursively discover network neighbors by
    querying CDP (Cisco Discovery Protocol) or LLDP neighbor tables. Builds
    a topology map without requiring SNMP or external discovery tools.

Usage:
    python cdp_lldp_crawler.py --host 192.168.1.1 --username admin --password secret
    python cdp_lldp_crawler.py --host 192.168.1.1 -u admin -p secret --depth 3 --protocol lldp
    python cdp_lldp_crawler.py --host 192.168.1.1 -u admin -p secret --output topology.json

Prerequisites:
    pip install netmiko
    CDP or LLDP must be enabled on target devices.
    SSH access required with privilege level sufficient to run show commands.
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
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def parse_cdp_neighbors(output):
    neighbors = []
    blocks = re.split(r"-{10,}", output)
    for block in blocks:
        hostname_m = re.search(r"Device ID:\s*(\S+)", block)
        ip_m = re.search(r"IP(?:v4)? [Aa]ddress:\s*(\d+\.\d+\.\d+\.\d+)", block)
        platform_m = re.search(r"Platform:\s*([^,\n]+)", block)
        port_m = re.search(r"Interface:\s*(\S+),\s*Port ID.*?:\s*(\S+)", block)
        if hostname_m and ip_m:
            neighbors.append({
                "hostname": hostname_m.group(1).split(".")[0],
                "ip": ip_m.group(1),
                "platform": platform_m.group(1).strip() if platform_m else "unknown",
                "local_port": port_m.group(1) if port_m else "unknown",
                "remote_port": port_m.group(2) if port_m else "unknown",
            })
    return neighbors


def parse_lldp_neighbors(output):
    neighbors = []
    blocks = re.split(r"-{10,}", output)
    for block in blocks:
        hostname_m = re.search(r"System Name:\s*(\S+)", block)
        ip_m = re.search(r"(?:Management Addresses?|IP address|IP).*?(\d+\.\d+\.\d+\.\d+)", block, re.DOTALL)
        cap_m = re.search(r"System Capabilities:\s*(.+)", block)
        local_m = re.search(r"Local Intf:\s*(\S+)", block)
        port_m = re.search(r"Port id:\s*(\S+)", block)
        if hostname_m and ip_m:
            neighbors.append({
                "hostname": hostname_m.group(1).split(".")[0],
                "ip": ip_m.group(1),
                "platform": cap_m.group(1).strip() if cap_m else "unknown",
                "local_port": local_m.group(1) if local_m else "unknown",
                "remote_port": port_m.group(1) if port_m else "unknown",
            })
    return neighbors


def query_device(host, username, password, device_type, protocol):
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "timeout": 15,
        "session_timeout": 30,
    }
    try:
        with ConnectHandler(**device) as conn:
            hostname = conn.find_prompt().rstrip("#>").strip()
            logger.info("Connected to %s (%s)", hostname, host)
            if protocol == "cdp":
                output = conn.send_command("show cdp neighbors detail", read_timeout=30)
                neighbors = parse_cdp_neighbors(output)
            else:
                output = conn.send_command("show lldp neighbors detail", read_timeout=30)
                neighbors = parse_lldp_neighbors(output)
            logger.info("Found %d neighbor(s) on %s", len(neighbors), hostname)
            return hostname, neighbors
    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s", host)
    except NetmikoTimeoutException:
        logger.error("Connection timed out for %s", host)
    except Exception as exc:
        logger.error("Failed to query %s: %s", host, exc)
    return None, []


def crawl_topology(seed_host, username, password, device_type, protocol, max_depth):
    topology = {}
    visited = set()
    queue = deque([(seed_host, 0)])

    while queue:
        host, depth = queue.popleft()
        if host in visited or depth > max_depth:
            continue
        visited.add(host)

        hostname, neighbors = query_device(host, username, password, device_type, protocol)
        if hostname is None:
            continue

        topology[host] = {
            "hostname": hostname,
            "neighbors": neighbors,
            "depth": depth,
        }

        if depth < max_depth:
            for neighbor in neighbors:
                ip = neighbor["ip"]
                if ip not in visited:
                    queue.append((ip, depth + 1))

    return topology


def print_topology(topology):
    print("\n" + "=" * 60)
    print("NETWORK TOPOLOGY DISCOVERY RESULTS")
    print("=" * 60)
    total_links = sum(len(v["neighbors"]) for v in topology.values())
    print(f"Devices discovered: {len(topology)}")
    print(f"Total adjacencies:  {total_links}")
    print()

    for ip, info in sorted(topology.items(), key=lambda x: (x[1]["depth"], x[1]["hostname"])):
        indent = "  " * info["depth"]
        prefix = "└─ " if info["depth"] > 0 else ""
        print(f"{indent}{prefix}[{info['hostname']}] {ip}  (hop {info['depth']})")
        for n in info["neighbors"]:
            reached = "✓" if n["ip"] in topology else "○"
            print(f"{indent}    {reached}  {n['hostname']} ({n['ip']})  "
                  f"{n['local_port']} → {n['remote_port']}  [{n['platform']}]")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Discover network topology by walking CDP/LLDP neighbor tables."
    )
    parser.add_argument("--host", "-H", required=True, help="Seed device IP or hostname")
    parser.add_argument("--username", "-u", required=True, help="SSH username")
    parser.add_argument("--password", "-p", required=True, help="SSH password")
    parser.add_argument(
        "--device-type", "-t", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument(
        "--protocol", choices=["cdp", "lldp"], default="cdp",
        help="Neighbor discovery protocol (default: cdp)",
    )
    parser.add_argument(
        "--depth", "-d", type=int, default=2,
        help="Maximum hop depth to crawl (default: 2)",
    )
    parser.add_argument(
        "--output", "-o",
        help="Write topology to this JSON file",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info(
        "Starting %s crawl from %s (max depth: %d)",
        args.protocol.upper(), args.host, args.depth,
    )

    topology = crawl_topology(
        args.host, args.username, args.password,
        args.device_type, args.protocol, args.depth,
    )

    if not topology:
        logger.error("No devices discovered. Check connectivity and credentials.")
        sys.exit(1)

    print_topology(topology)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(topology, fh, indent=2)
        logger.info("Topology written to %s", args.output)


if __name__ == "__main__":
    main()
```