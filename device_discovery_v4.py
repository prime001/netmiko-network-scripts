cdp_lldp_mapper.py - Network topology discovery via CDP/LLDP

Purpose:
    Discovers network topology by querying CDP (Cisco Discovery Protocol) or
    LLDP (Link Layer Discovery Protocol) neighbor tables from a seed device.
    Optionally walks discovered neighbors recursively (BFS) to map multi-hop
    topology. Outputs a human-readable summary and optionally a JSON file.

Usage:
    python cdp_lldp_mapper.py -d 192.168.1.1 -u admin -p secret
    python cdp_lldp_mapper.py -d 192.168.1.1 -u admin -p secret --depth 2
    python cdp_lldp_mapper.py -d 192.168.1.1 -u admin -p secret --protocol lldp --output topo.json

Prerequisites:
    pip install netmiko
    SSH access to the seed device; CDP or LLDP must be enabled.
    Supported device types: cisco_ios, cisco_xe, cisco_nxos, arista_eos
"""

import argparse
import json
import logging
import sys
from collections import deque

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

CDP_COMMAND = "show cdp neighbors detail"
LLDP_COMMAND = "show lldp neighbors detail"

SUPPORTED_TYPES = ["cisco_ios", "cisco_xe", "cisco_nxos", "arista_eos"]


def parse_cdp_output(output):
    """Return list of neighbor dicts from 'show cdp neighbors detail' output."""
    neighbors = []
    current = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Device ID:"):
            if current.get("device_id"):
                neighbors.append(current)
            current = {"device_id": line.split("Device ID:")[-1].strip()}
        elif line.startswith("IP address:") and current:
            current.setdefault("ip_addresses", []).append(line.split("IP address:")[-1].strip())
        elif line.startswith("Interface:") and current:
            parts = line.split(",")
            current["local_interface"] = parts[0].split("Interface:")[-1].strip()
            if len(parts) > 1:
                current["remote_interface"] = parts[1].split("port:")[-1].strip()
        elif line.startswith("Platform:") and current:
            current["platform"] = line.split(",")[0].split("Platform:")[-1].strip()
    if current.get("device_id"):
        neighbors.append(current)
    return neighbors


def parse_lldp_output(output):
    """Return list of neighbor dicts from 'show lldp neighbors detail' output."""
    neighbors = []
    current = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Local Intf:") or line.startswith("Interface:"):
            if current.get("device_id"):
                neighbors.append(current)
            key = "Local Intf:" if "Local Intf:" in line else "Interface:"
            current = {"local_interface": line.split(key)[-1].strip()}
        elif "System Name:" in line and current:
            current.setdefault("device_id", line.split("System Name:")[-1].strip())
        elif line.startswith("IP:") and current:
            current.setdefault("ip_addresses", []).append(line.split("IP:")[-1].strip())
        elif "Port Description:" in line and current:
            current["remote_interface"] = line.split("Port Description:")[-1].strip()
        elif "System Description:" in line and current:
            current["platform"] = line.split("System Description:")[-1].strip()[:60]
    if current.get("device_id"):
        neighbors.append(current)
    return neighbors


def query_device(host, username, password, device_type, protocol, secret=None):
    """Connect to host and return (hostname, neighbors_list) or (None, None) on failure."""
    params = {"device_type": device_type, "host": host, "username": username, "password": password}
    if secret:
        params["secret"] = secret

    command = LLDP_COMMAND if protocol == "lldp" else CDP_COMMAND
    try:
        logger.info("Connecting to %s", host)
        with ConnectHandler(**params) as conn:
            hostname = conn.find_prompt().rstrip("#>").strip()
            output = conn.send_command(command)
        logger.info("Collected %s data from %s (%s)", protocol.upper(), hostname, host)
    except NetmikoAuthenticationException:
        logger.error("Authentication failed: %s", host)
        return None, None
    except NetmikoTimeoutException:
        logger.error("Connection timed out: %s", host)
        return None, None
    except Exception as exc:
        logger.error("Error connecting to %s: %s", host, exc)
        return None, None

    parser = parse_lldp_output if protocol == "lldp" else parse_cdp_output
    return hostname, parser(output)


def discover_topology(seed, username, password, device_type, protocol, max_depth, secret=None):
    """BFS from seed device up to max_depth hops; returns topology dict keyed by IP."""
    topology = {}
    visited = set()
    queue = deque([(seed, 0)])

    while queue:
        host, depth = queue.popleft()
        if host in visited or depth > max_depth:
            continue
        visited.add(host)

        hostname, neighbors = query_device(host, username, password, device_type, protocol, secret)
        if hostname is None:
            continue

        topology[host] = {"hostname": hostname, "neighbors": neighbors or []}

        if depth < max_depth:
            for nbr in neighbors or []:
                for ip in nbr.get("ip_addresses", []):
                    if ip and ip not in visited:
                        queue.append((ip, depth + 1))

    return topology


def print_topology(topology):
    print("\n=== Network Topology ===\n")
    for host, data in topology.items():
        print(f"Device: {data['hostname']} ({host})")
        neighbors = data.get("neighbors", [])
        if not neighbors:
            print("  No neighbors discovered")
        for nbr in neighbors:
            device_id = nbr.get("device_id", "Unknown")
            local = nbr.get("local_interface", "?")
            remote = nbr.get("remote_interface", "?")
            ips = ", ".join(nbr.get("ip_addresses", [])) or "no IP"
            platform = nbr.get("platform", "")
            print(f"  ├─ {device_id} [{ips}]  {platform}")
            print(f"  │   {local} <-> {remote}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Map network topology via CDP/LLDP neighbor tables."
    )
    parser.add_argument("-d", "--device", required=True, help="Seed device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("-s", "--secret", default=None, help="Enable secret")
    parser.add_argument(
        "-t", "--device-type", default="cisco_ios", choices=SUPPORTED_TYPES,
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument(
        "--protocol", choices=["cdp", "lldp"], default="cdp",
        help="Discovery protocol (default: cdp)",
    )
    parser.add_argument(
        "--depth", type=int, default=0,
        help="Hop depth for recursive walk; 0 = seed only (default: 0)",
    )
    parser.add_argument("--output", default=None, help="Write JSON topology to this file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    topology = discover_topology(
        seed=args.device,
        username=args.username,
        password=args.password,
        device_type=args.device_type,
        protocol=args.protocol,
        max_depth=args.depth,
        secret=args.secret,
    )

    if not topology:
        logger.error("No topology data collected. Check connectivity and credentials.")
        sys.exit(1)

    print_topology(topology)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(topology, fh, indent=2)
        logger.info("Topology written to %s", args.output)


if __name__ == "__main__":
    main()