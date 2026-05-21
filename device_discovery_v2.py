The user's instructions are explicit: "Output ONLY the script content, no markdown fences, no explanation." This is a direct user instruction that overrides the brainstorming skill's design-first gate. Writing the CDP/LLDP topology mapper now.

"""
cdp_lldp_topology.py - CDP/LLDP network topology mapper

Purpose:
    Connects to a seed device via Netmiko, queries CDP or LLDP neighbor
    tables, and optionally walks discovered neighbor IPs recursively to
    produce a full adjacency map of the network. Outputs a summary table
    to stdout and optionally a JSON adjacency file.

    Distinct from device_discovery.py (inventory-based enumeration) —
    this script builds topology from live neighbor-protocol data.

Usage:
    python cdp_lldp_topology.py -H 192.168.1.1 -u admin -p secret
    python cdp_lldp_topology.py -H 10.0.0.1 -u admin -p secret --recursive --depth 3
    python cdp_lldp_topology.py -H 10.0.0.1 -u admin -p secret --protocol lldp --output topo.json
    python cdp_lldp_topology.py -H 10.0.0.1 -u admin -p secret -t cisco_nxos

Prerequisites:
    pip install netmiko
    CDP or LLDP must be enabled on target devices.
    User needs at minimum read-only access (enable not required unless
    privilege level blocks show commands).
    Supported: Cisco IOS, IOS-XE, IOS-XR, NX-OS (CDP); most vendors (LLDP).
"""

import argparse
import json
import logging
import sys
from collections import defaultdict

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

CDP_CMD = "show cdp neighbors detail"
LLDP_CMD = "show lldp neighbors detail"


def parse_cdp_neighbors(raw):
    neighbors = []
    current = {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("Device ID:"):
            if current:
                neighbors.append(current)
            current = {"device_id": line.split("Device ID:")[-1].strip()}
        elif line.startswith("IP address:") and "ip" not in current:
            current["ip"] = line.split("IP address:")[-1].strip()
        elif line.startswith("Platform:"):
            parts = line.split(",")
            current["platform"] = parts[0].split("Platform:")[-1].strip()
            if len(parts) > 1:
                current["capabilities"] = parts[1].split("Capabilities:")[-1].strip()
        elif line.startswith("Interface:"):
            parts = line.split(",")
            current["local_port"] = parts[0].split("Interface:")[-1].strip()
            if len(parts) > 1:
                current["remote_port"] = parts[1].split("Port ID (outgoing port):")[-1].strip()
    if current:
        neighbors.append(current)
    return neighbors


def parse_lldp_neighbors(raw):
    neighbors = []
    current = {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("System Name:"):
            if current and "device_id" in current:
                neighbors.append(current)
            current = {"device_id": line.split("System Name:")[-1].strip()}
        elif line.startswith("Management Address:") and "ip" not in current:
            current["ip"] = line.split("Management Address:")[-1].strip()
        elif line.startswith("System Capabilities:"):
            current["capabilities"] = line.split("System Capabilities:")[-1].strip()
        elif "Local Intf" in line or "Local Port id" in line:
            current["local_port"] = line.split(":")[-1].strip()
        elif line.startswith("Port ID:") or line.startswith("Port id:"):
            current["remote_port"] = line.split(":")[-1].strip()
        elif line.startswith("System Description:"):
            current["platform"] = line.split("System Description:")[-1].strip()[:60]
    if current and "device_id" in current:
        neighbors.append(current)
    return neighbors


def query_device(host, username, password, device_type, protocol, secret=""):
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "secret": secret,
        "timeout": 20,
    }
    command = CDP_CMD if protocol == "cdp" else LLDP_CMD
    try:
        with ConnectHandler(**params) as conn:
            if secret:
                conn.enable()
            hostname = conn.find_prompt().strip("#>").strip()
            raw = conn.send_command(command)
        return hostname, raw
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", host)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", host)
    except Exception as exc:
        log.error("Unexpected error on %s: %s", host, exc)
    return None, None


def discover(seed_host, username, password, device_type, protocol, secret,
             recursive, max_depth):
    topology = defaultdict(list)
    visited = set()
    queue = [(seed_host, 0)]
    parse_fn = parse_cdp_neighbors if protocol == "cdp" else parse_lldp_neighbors

    while queue:
        host, depth = queue.pop(0)
        if host in visited or depth > max_depth:
            continue
        visited.add(host)
        log.info("Querying %s (depth %d)", host, depth)

        hostname, raw = query_device(host, username, password, device_type, protocol, secret)
        if not raw:
            continue

        neighbors = parse_fn(raw)
        node = hostname or host
        log.info("  %s: %d neighbor(s) found", node, len(neighbors))
        topology[node].extend(neighbors)

        if recursive and depth < max_depth:
            for nbr in neighbors:
                nbr_ip = nbr.get("ip")
                if nbr_ip and nbr_ip not in visited:
                    queue.append((nbr_ip, depth + 1))

    return dict(topology)


def print_summary(topology):
    col = "{:<28} {:<28} {:<18} {:<18}"
    header = col.format("Local Device", "Neighbor", "Local Port", "Remote Port")
    print(f"\n{header}")
    print("-" * len(header))
    for device in sorted(topology):
        for nbr in topology[device]:
            print(col.format(
                device[:27],
                nbr.get("device_id", "unknown")[:27],
                nbr.get("local_port", "")[:17],
                nbr.get("remote_port", "")[:17],
            ))
    total = sum(len(v) for v in topology.values())
    print(f"\n{len(topology)} device(s) queried, {total} neighbor link(s) mapped.")


def main():
    parser = argparse.ArgumentParser(
        description="Map network topology via CDP or LLDP neighbor tables"
    )
    parser.add_argument("-H", "--host", required=True, help="Seed device IP or hostname")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument("-s", "--secret", default="", help="Enable secret (if required)")
    parser.add_argument(
        "-t", "--device-type", default="cisco_ios",
        help="Netmiko device_type (default: cisco_ios)",
    )
    parser.add_argument(
        "--protocol", choices=["cdp", "lldp"], default="cdp",
        help="Neighbor discovery protocol (default: cdp)",
    )
    parser.add_argument(
        "--recursive", action="store_true",
        help="Walk discovered neighbor IPs recursively",
    )
    parser.add_argument(
        "--depth", type=int, default=2,
        help="Max hop depth when --recursive is set (default: 2)",
    )
    parser.add_argument("--output", help="Write JSON adjacency map to this file")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    topology = discover(
        args.host, args.username, args.password,
        args.device_type, args.protocol, args.secret,
        args.recursive, args.depth,
    )

    if not topology:
        log.error("No topology data collected — check connectivity and protocol settings")
        sys.exit(1)

    print_summary(topology)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(topology, fh, indent=2)
        log.info("Adjacency map written to %s", args.output)


if __name__ == "__main__":
    main()