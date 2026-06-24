lldp_neighbor_crawler.py - LLDP/CDP Neighbor Discovery Crawler

Purpose:
    Discovers network topology by crawling LLDP and CDP neighbor tables
    starting from a seed device. Optionally performs multi-hop discovery
    to map the full reachable topology.

Usage:
    python lldp_neighbor_crawler.py -H 192.168.1.1 -u admin -p secret
    python lldp_neighbor_crawler.py -H 192.168.1.1 -u admin -p secret --depth 2
    python lldp_neighbor_crawler.py -H 192.168.1.1 -u admin -p secret --protocol cdp --output topology.json

Prerequisites:
    pip install netmiko
    LLDP or CDP must be enabled on target devices.
    SSH access and valid credentials required on each device being crawled.
"""

import argparse
import json
import logging
import re
import sys
from collections import deque

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def get_lldp_neighbors(conn):
    """Return neighbor list from LLDP detail output."""
    output = conn.send_command("show lldp neighbors detail", use_textfsm=True)
    if isinstance(output, list):
        return output
    neighbors = []
    for block in re.split(r"(?=^-{5,})", output, flags=re.MULTILINE):
        neighbor = {}
        m = re.search(r"System Name:\s+(\S+)", block)
        if m:
            neighbor["hostname"] = m.group(1)
        m = re.search(r"Management Addresses[^:]*:\s+(\d+\.\d+\.\d+\.\d+)", block)
        if m:
            neighbor["mgmt_ip"] = m.group(1)
        m = re.search(r"Port Description:\s+(.+)", block)
        if m:
            neighbor["remote_port"] = m.group(1).strip()
        if neighbor.get("hostname"):
            neighbors.append(neighbor)
    return neighbors


def get_cdp_neighbors(conn):
    """Return neighbor list from CDP detail output."""
    output = conn.send_command("show cdp neighbors detail", use_textfsm=True)
    if isinstance(output, list):
        return output
    neighbors = []
    for block in re.split(r"(?=^-{5,})", output, flags=re.MULTILINE):
        neighbor = {}
        m = re.search(r"Device ID:\s+(\S+)", block)
        if m:
            neighbor["hostname"] = m.group(1).rstrip("()")
        m = re.search(r"IP address:\s+(\d+\.\d+\.\d+\.\d+)", block, re.IGNORECASE)
        if m:
            neighbor["mgmt_ip"] = m.group(1)
        m = re.search(r"Port ID \(outgoing port\):\s+(.+)", block)
        if m:
            neighbor["remote_port"] = m.group(1).strip()
        if neighbor.get("hostname"):
            neighbors.append(neighbor)
    return neighbors


def discover_neighbors(host, username, password, device_type, protocol, secret=""):
    """Connect to a single device and return (hostname, neighbor_list)."""
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "secret": secret,
        "timeout": 15,
        "fast_cli": False,
    }
    try:
        with ConnectHandler(**params) as conn:
            if secret:
                conn.enable()
            hostname = conn.find_prompt().rstrip("#>").strip()
            logger.info("Connected to %s (%s)", hostname, host)
            neighbors = get_lldp_neighbors(conn) if protocol == "lldp" else get_cdp_neighbors(conn)
            return hostname, neighbors
    except NetmikoAuthenticationException:
        logger.error("Authentication failed: %s", host)
    except NetmikoTimeoutException:
        logger.error("Connection timed out: %s", host)
    except Exception as exc:
        logger.error("Error on %s: %s", host, exc)
    return None, []


def crawl(seed_host, username, password, device_type, protocol, secret, max_depth):
    """BFS crawl from seed device up to max_depth hops."""
    topology = {}
    visited = {seed_host}
    queue = deque([(seed_host, 0)])

    while queue:
        host, depth = queue.popleft()
        hostname, neighbors = discover_neighbors(
            host, username, password, device_type, protocol, secret
        )
        if hostname is None:
            continue
        topology[host] = {"hostname": hostname, "neighbors": neighbors}
        if depth < max_depth:
            for nbr in neighbors:
                mgmt_ip = nbr.get("mgmt_ip") or nbr.get("management_ip", "")
                if mgmt_ip and mgmt_ip not in visited:
                    visited.add(mgmt_ip)
                    queue.append((mgmt_ip, depth + 1))

    return topology


def print_topology(topology):
    """Print a human-readable topology summary."""
    print(f"\n{'=' * 60}")
    print(f"  Topology — {len(topology)} device(s) discovered")
    print(f"{'=' * 60}")
    for ip, data in topology.items():
        print(f"\n[{data['hostname']}]  {ip}")
        neighbors = data.get("neighbors", [])
        if not neighbors:
            print("  (no neighbors found)")
            continue
        for nbr in neighbors:
            hn = nbr.get("hostname") or nbr.get("destination_host", "unknown")
            port = nbr.get("remote_port") or nbr.get("port_id", "")
            mgmt = nbr.get("mgmt_ip") or nbr.get("management_ip", "")
            print(f"  -> {hn:<30} port={port}  mgmt={mgmt}")


def main():
    parser = argparse.ArgumentParser(
        description="Crawl LLDP/CDP neighbor tables to map network topology"
    )
    parser.add_argument("-H", "--host", required=True, help="Seed device IP/hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("-s", "--secret", default="", help="Enable secret")
    parser.add_argument(
        "-t", "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument(
        "--protocol", choices=["lldp", "cdp"], default="lldp",
        help="Discovery protocol (default: lldp)",
    )
    parser.add_argument(
        "--depth", type=int, default=0,
        help="Hops beyond seed device to crawl (default: 0)",
    )
    parser.add_argument("--output", help="Write JSON results to this file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    topology = crawl(
        seed_host=args.host,
        username=args.username,
        password=args.password,
        device_type=args.device_type,
        protocol=args.protocol,
        secret=args.secret,
        max_depth=args.depth,
    )

    if not topology:
        logger.error("No devices discovered. Check connectivity and credentials.")
        sys.exit(1)

    print_topology(topology)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(topology, fh, indent=2)
        logger.info("Results written to %s", args.output)


if __name__ == "__main__":
    main()