cdp_lldp_mapper.py - Network topology mapper via CDP/LLDP neighbor tables

Walks the network starting from a seed device, collecting CDP or LLDP
neighbor information at each hop to build a topology map. Useful for
auditing undocumented networks, validating cabling, or generating input
for diagram tools.

Usage:
    python cdp_lldp_mapper.py -d 10.0.0.1 -u admin -p secret
    python cdp_lldp_mapper.py -d 10.0.0.1 -u admin --depth 3 --protocol lldp
    python cdp_lldp_mapper.py -d 10.0.0.1 -u admin --depth 2 --output topology.json

Prerequisites:
    pip install netmiko
    CDP or LLDP must be enabled on target devices
    SSH access with credentials that have 'show' privilege
"""

import argparse
import getpass
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
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def parse_cdp_neighbors(output):
    neighbors = []
    for block in re.split(r"-{10,}", output):
        device_id = re.search(r"Device ID:\s*(\S+)", block)
        ip = re.search(r"IP(?:v4)? [Aa]ddress:\s*(\d{1,3}(?:\.\d{1,3}){3})", block)
        platform = re.search(r"Platform:\s*(.+?),", block)
        local_intf = re.search(r"Interface:\s*(\S+),", block)
        remote_intf = re.search(r"Port ID \(outgoing port\):\s*(\S+)", block)

        if device_id and ip:
            neighbors.append({
                "device_id": device_id.group(1),
                "ip": ip.group(1),
                "platform": platform.group(1).strip() if platform else "unknown",
                "local_interface": local_intf.group(1) if local_intf else "unknown",
                "remote_interface": remote_intf.group(1) if remote_intf else "unknown",
            })
    return neighbors


def parse_lldp_neighbors(output):
    neighbors = []
    for block in re.split(r"-{10,}", output):
        device_id = re.search(r"System Name:\s*(\S+)", block)
        if not device_id:
            device_id = re.search(r"Chassis id:\s*(\S+)", block)
        ip = re.search(
            r"Management Addresses.*?IP:\s*(\d{1,3}(?:\.\d{1,3}){3})",
            block,
            re.DOTALL,
        )
        local_intf = re.search(r"Local Intf:\s*(\S+)", block)
        remote_intf = re.search(r"Port id:\s*(\S+)", block)

        if device_id and ip:
            neighbors.append({
                "device_id": device_id.group(1),
                "ip": ip.group(1),
                "platform": "unknown",
                "local_interface": local_intf.group(1) if local_intf else "unknown",
                "remote_interface": remote_intf.group(1) if remote_intf else "unknown",
            })
    return neighbors


def query_device(host, username, password, device_type, protocol):
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "timeout": 15,
    }
    try:
        logger.info("Connecting to %s", host)
        with ConnectHandler(**params) as conn:
            hostname = conn.find_prompt().strip("#> ")
            if protocol == "cdp":
                output = conn.send_command("show cdp neighbors detail", read_timeout=30)
                neighbors = parse_cdp_neighbors(output)
            else:
                output = conn.send_command("show lldp neighbors detail", read_timeout=30)
                neighbors = parse_lldp_neighbors(output)
            logger.info("%s (%s): %d neighbor(s) found", hostname, host, len(neighbors))
            return hostname, neighbors
    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s", host)
    except NetmikoTimeoutException:
        logger.error("Connection timed out for %s", host)
    except Exception as exc:
        logger.error("Failed to query %s: %s", host, exc)
    return None, []


def discover_topology(seed_host, username, password, device_type, protocol, max_depth):
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

        topology[host] = {"hostname": hostname, "depth": depth, "neighbors": neighbors}

        if depth < max_depth:
            for n in neighbors:
                if n["ip"] not in visited:
                    queue.append((n["ip"], depth + 1))

    return topology


def print_topology(topology):
    print(f"\n{'=' * 62}")
    print(f"  Topology Map — {len(topology)} device(s) discovered")
    print(f"{'=' * 62}")
    for ip, info in sorted(topology.items(), key=lambda x: x[1]["depth"]):
        print(f"\n  [{info['hostname']}]  {ip}  (hop {info['depth']})")
        if info["neighbors"]:
            for n in info["neighbors"]:
                print(
                    f"    -> {n['device_id']} ({n['ip']})  "
                    f"{n['local_interface']} <-> {n['remote_interface']}  "
                    f"[{n['platform']}]"
                )
        else:
            print("    (no neighbors found)")
    print(f"\n{'=' * 62}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Map network topology via CDP/LLDP starting from a seed device",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-d", "--device", required=True, help="Seed device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument(
        "-t", "--device-type",
        default="cisco_ios",
        metavar="TYPE",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument(
        "--protocol",
        choices=["cdp", "lldp"],
        default="cdp",
        help="Neighbor discovery protocol (default: cdp)",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=1,
        help="Max hops to traverse from seed device (default: 1)",
    )
    parser.add_argument("--output", metavar="FILE", help="Write JSON results to file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.depth < 0:
        parser.error("--depth must be >= 0")
    if args.depth > 5:
        logger.warning("depth=%d may take a long time on large networks", args.depth)

    password = args.password or getpass.getpass(f"Password for {args.username}@{args.device}: ")

    topology = discover_topology(
        seed_host=args.device,
        username=args.username,
        password=password,
        device_type=args.device_type,
        protocol=args.protocol,
        max_depth=args.depth,
    )

    if not topology:
        logger.error("No devices discovered — check connectivity and credentials")
        sys.exit(1)

    print_topology(topology)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(topology, fh, indent=2)
        logger.info("Results written to %s", args.output)


if __name__ == "__main__":
    main()