cdp_lldp_mapper.py — CDP/LLDP Neighbor Topology Mapper

Purpose:
    Connects to a seed network device and walks CDP or LLDP neighbor tables
    to build a layer-2/layer-3 topology map. Supports single-hop inspection
    or recursive BFS crawling to discover the full neighbor graph up to a
    configurable depth.

Usage:
    python cdp_lldp_mapper.py -H 192.168.1.1 -u admin -p secret
    python cdp_lldp_mapper.py -H 192.168.1.1 -u admin --recurse --max-depth 3
    python cdp_lldp_mapper.py -H 192.168.1.1 -u admin --protocol lldp --output topo.json

Prerequisites:
    pip install netmiko
    CDP or LLDP must be enabled on target devices.
    SSH access with privilege sufficient to run neighbor detail commands.
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
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def parse_cdp_neighbors(output):
    """Return list of neighbor dicts from 'show cdp neighbors detail' output."""
    neighbors = []
    for block in re.split(r"-{10,}", output):
        nbr = {}
        m = re.search(r"Device ID:\s*(\S+)", block)
        if m:
            nbr["device_id"] = m.group(1).split(".")[0]
        m = re.search(r"IP(?:v4)? [Aa]ddress:\s*(\d+\.\d+\.\d+\.\d+)", block)
        if m:
            nbr["mgmt_ip"] = m.group(1)
        m = re.search(r"Platform:\s*([^,\n]+)", block)
        if m:
            nbr["platform"] = m.group(1).strip()
        m = re.search(r"Interface:\s*(\S+),", block)
        if m:
            nbr["local_intf"] = m.group(1)
        m = re.search(r"Port ID \(outgoing port\):\s*(\S+)", block)
        if m:
            nbr["remote_intf"] = m.group(1)
        if "device_id" in nbr and "mgmt_ip" in nbr:
            neighbors.append(nbr)
    return neighbors


def parse_lldp_neighbors(output):
    """Return list of neighbor dicts from 'show lldp neighbors detail' output."""
    neighbors = []
    for block in re.split(r"-{5,}", output):
        nbr = {}
        m = re.search(r"System Name:\s*(\S+)", block)
        if m:
            nbr["device_id"] = m.group(1)
        m = re.search(r"Management Address[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", block)
        if m:
            nbr["mgmt_ip"] = m.group(1)
        m = re.search(r"System Description[^:]*:\n?\s*(.+)", block)
        if m:
            nbr["platform"] = m.group(1).strip()[:60]
        m = re.search(r"Local Intf:\s*(\S+)", block)
        if m:
            nbr["local_intf"] = m.group(1)
        m = re.search(r"Port id:\s*(\S+)", block)
        if m:
            nbr["remote_intf"] = m.group(1)
        if "device_id" in nbr and "mgmt_ip" in nbr:
            neighbors.append(nbr)
    return neighbors


def query_device(host, username, password, device_type, protocol, secret=""):
    """Connect to a device and return (hostname, neighbors) or (None, []) on failure."""
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "secret": secret,
        "timeout": 30,
        "conn_timeout": 10,
    }
    try:
        with ConnectHandler(**params) as conn:
            if secret:
                conn.enable()
            hostname = conn.find_prompt().rstrip("#>").lstrip()
            if protocol == "cdp":
                raw = conn.send_command("show cdp neighbors detail", read_timeout=60)
                neighbors = parse_cdp_neighbors(raw)
            else:
                raw = conn.send_command("show lldp neighbors detail", read_timeout=60)
                neighbors = parse_lldp_neighbors(raw)
            log.info("%-20s  %s  →  %d neighbor(s)", hostname, host, len(neighbors))
            return hostname, neighbors
    except NetmikoAuthenticationException:
        log.error("Auth failed: %s", host)
    except NetmikoTimeoutException:
        log.error("Timeout: %s", host)
    except Exception as exc:
        log.error("Error on %s: %s", host, exc)
    return None, []


def build_topology(seed_ip, username, password, device_type, protocol, secret, max_depth):
    """BFS from seed device; return topology dict keyed by management IP."""
    topology = {}
    visited = set()
    queue = deque([(seed_ip, 0)])

    while queue:
        ip, depth = queue.popleft()
        if ip in visited or depth > max_depth:
            continue
        visited.add(ip)

        hostname, neighbors = query_device(ip, username, password, device_type, protocol, secret)
        if hostname is None:
            continue

        topology[ip] = {"hostname": hostname, "depth": depth, "neighbors": neighbors}

        if depth < max_depth:
            for nbr in neighbors:
                nbr_ip = nbr.get("mgmt_ip")
                if nbr_ip and nbr_ip not in visited:
                    queue.append((nbr_ip, depth + 1))

    return topology


def render_topology(topology):
    """Print a human-readable adjacency table."""
    print(f"\n{'='*62}")
    print(f"  Topology  ({len(topology)} device(s) discovered)")
    print(f"{'='*62}")
    for ip, data in sorted(topology.items(), key=lambda x: x[1]["depth"]):
        indent = "  " * data["depth"]
        print(f"\n{indent}[{data['hostname']}]  {ip}")
        for nbr in data["neighbors"]:
            print(
                f"{indent}  -> {nbr.get('device_id', '?'):<28} "
                f"{nbr.get('mgmt_ip', 'N/A'):<16} "
                f"{nbr.get('local_intf', '?')} -> {nbr.get('remote_intf', '?')}"
            )
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Map network topology via CDP or LLDP neighbor tables."
    )
    parser.add_argument("-H", "--host", required=True, help="Seed device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("-s", "--secret", default="", help="Enable secret")
    parser.add_argument(
        "-t", "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)"
    )
    parser.add_argument(
        "--protocol", choices=["cdp", "lldp"], default="cdp",
        help="Discovery protocol (default: cdp)"
    )
    parser.add_argument(
        "--recurse", action="store_true",
        help="Recursively crawl neighbor devices"
    )
    parser.add_argument(
        "--max-depth", type=int, default=2,
        help="Max hops to crawl when --recurse is set (default: 2)"
    )
    parser.add_argument("--output", help="Write topology JSON to this file")
    parser.add_argument("--debug", action="store_true", help="Verbose debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass("SSH password: ")
    depth = args.max_depth if args.recurse else 0

    topology = build_topology(
        args.host, args.username, password,
        args.device_type, args.protocol, args.secret, depth
    )

    if not topology:
        log.error("No devices reachable. Verify credentials and connectivity.")
        sys.exit(1)

    render_topology(topology)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(topology, fh, indent=2)
        log.info("Topology saved to %s", args.output)


if __name__ == "__main__":
    main()