```python
"""
CDP/LLDP Topology Mapper - Discovers network topology via neighbor protocols.

Purpose:
    Connects to a seed device and queries CDP (Cisco) or LLDP neighbor tables
    to map the physical network topology. Optionally recurses through discovered
    neighbors to build a multi-hop topology graph.

Usage:
    python topology_mapper.py -H 192.168.1.1 -u admin -p secret
    python topology_mapper.py -H 192.168.1.1 -u admin -p secret --recursive --depth 3
    python topology_mapper.py -H 192.168.1.1 -u admin -p secret --protocol lldp --json

Prerequisites:
    pip install netmiko
    CDP or LLDP must be enabled on target devices.
    SSH access with privilege sufficient to run 'show cdp/lldp neighbors detail'.
    ntc-templates installed for TextFSM parsing (pip install ntc-templates).
"""

import argparse
import json
import logging
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


def get_cdp_neighbors(connection):
    output = connection.send_command("show cdp neighbors detail", use_textfsm=True)
    if isinstance(output, str):
        logger.warning("TextFSM parse failed; raw output returned — ntc-templates installed?")
        return []
    neighbors = []
    for entry in output:
        neighbors.append({
            "destination_host": entry.get("destination_host", ""),
            "management_ip": entry.get("management_ip", ""),
            "platform": entry.get("platform", ""),
            "local_port": entry.get("local_port", ""),
            "remote_port": entry.get("remote_port", ""),
            "software_version": entry.get("software_version", ""),
        })
    return neighbors


def get_lldp_neighbors(connection):
    output = connection.send_command("show lldp neighbors detail", use_textfsm=True)
    if isinstance(output, str):
        logger.warning("TextFSM parse failed for LLDP; ntc-templates installed?")
        return []
    neighbors = []
    for entry in output:
        neighbors.append({
            "destination_host": entry.get("neighbor", entry.get("system_name", "")),
            "management_ip": entry.get("management_address", ""),
            "platform": entry.get("system_description", ""),
            "local_port": entry.get("local_interface", entry.get("local_port", "")),
            "remote_port": entry.get("neighbor_port_id", entry.get("remote_port", "")),
            "software_version": "",
        })
    return neighbors


def connect_to_device(host, username, password, device_type, port=22):
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "timeout": 15,
        "auth_timeout": 10,
    }
    try:
        conn = ConnectHandler(**params)
        logger.info("Connected to %s", host)
        return conn
    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s", host)
    except NetmikoTimeoutException:
        logger.error("Connection timed out for %s", host)
    except Exception as exc:
        logger.error("Cannot connect to %s: %s", host, exc)
    return None


def discover_topology(seed_host, username, password, device_type, protocol, max_depth, port):
    visited = {}
    queue = deque([(seed_host, 0)])
    queued = {seed_host}

    while queue:
        host, depth = queue.popleft()
        if host in visited:
            continue

        logger.info("Querying %s (depth %d/%d)", host, depth, max_depth)
        conn = connect_to_device(host, username, password, device_type, port)
        if conn is None:
            visited[host] = []
            continue

        try:
            neighbors = get_lldp_neighbors(conn) if protocol == "lldp" else get_cdp_neighbors(conn)
        except Exception as exc:
            logger.error("Neighbor query failed on %s: %s", host, exc)
            neighbors = []
        finally:
            conn.disconnect()

        visited[host] = neighbors
        logger.info("%d neighbor(s) found on %s", len(neighbors), host)

        if depth < max_depth:
            for nbr in neighbors:
                mgmt_ip = nbr.get("management_ip", "").strip()
                if mgmt_ip and mgmt_ip not in queued:
                    queued.add(mgmt_ip)
                    queue.append((mgmt_ip, depth + 1))

    return visited


def print_table(topology):
    col = (20, 25, 20, 16, 16, 16)
    header = (
        f"{'Device':<{col[0]}} {'Neighbor':<{col[1]}} {'Platform':<{col[2]}} "
        f"{'Local Port':<{col[3]}} {'Remote Port':<{col[4]}} {'Mgmt IP':<{col[5]}}"
    )
    print(header)
    print("-" * len(header))
    for device, neighbors in topology.items():
        if not neighbors:
            print(f"{device:<{col[0]}} (no neighbors or unreachable)")
            continue
        for nbr in neighbors:
            print(
                f"{device:<{col[0]}} "
                f"{nbr['destination_host']:<{col[1]}} "
                f"{nbr['platform'][:col[2] - 1]:<{col[2]}} "
                f"{nbr['local_port']:<{col[3]}} "
                f"{nbr['remote_port']:<{col[4]}} "
                f"{nbr['management_ip']:<{col[5]}}"
            )


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Map network topology using CDP or LLDP neighbor tables."
    )
    parser.add_argument("-H", "--host", required=True, help="Seed device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument(
        "-t", "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument(
        "--protocol", choices=["cdp", "lldp"], default="cdp",
        help="Neighbor discovery protocol (default: cdp)",
    )
    parser.add_argument(
        "--recursive", action="store_true",
        help="Follow neighbor management IPs to build multi-hop topology",
    )
    parser.add_argument(
        "--depth", type=int, default=1,
        help="Max hops when --recursive is set (default: 1)",
    )
    parser.add_argument(
        "--json", action="store_true", dest="output_json",
        help="Emit results as JSON instead of a table",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    return parser


if __name__ == "__main__":
    args = build_arg_parser().parse_args()

    max_depth = args.depth if args.recursive else 0
    topology = discover_topology(
        args.host,
        args.username,
        args.password,
        args.device_type,
        args.protocol,
        max_depth,
        args.port,
    )

    if args.output_json:
        print(json.dumps(topology, indent=2))
    else:
        print_table(topology)

    total = sum(len(v) for v in topology.values())
    logger.info(
        "Complete: %d device(s) queried, %d neighbor relationship(s) mapped",
        len(topology),
        total,
    )
    sys.exit(0)
```