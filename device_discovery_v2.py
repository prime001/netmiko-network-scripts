cdp_lldp_crawler.py - Network topology discovery via CDP/LLDP neighbor crawling.

Purpose:
    Discovers network topology by recursively querying CDP or LLDP neighbors
    starting from a seed device. Builds a map of device adjacencies without
    relying on IP scanning — uses the devices themselves as the source of truth
    for neighbor relationships. Useful for documenting unknown networks or
    verifying topology after changes.

Usage:
    python cdp_lldp_crawler.py --host 10.0.0.1 --username admin --password secret
    python cdp_lldp_crawler.py --host 10.0.0.1 -u admin -p secret --depth 2 --protocol lldp
    python cdp_lldp_crawler.py --host 10.0.0.1 -u admin -p secret --output topology.csv

Prerequisites:
    pip install netmiko
    CDP or LLDP must be enabled on target devices.
    SSH access required on all devices to be crawled recursively.
"""

import argparse
import csv
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


def parse_cdp_neighbors(output: str) -> list[dict]:
    neighbors = []
    blocks = re.split(r"-{10,}", output)
    for block in blocks:
        device_id = re.search(r"Device ID:\s*(\S+)", block)
        ip_addr = re.search(r"IP(?:v4)? [Aa]ddress:\s*(\d+\.\d+\.\d+\.\d+)", block)
        platform = re.search(r"Platform:\s*([^,]+)", block)
        local_iface = re.search(r"Interface:\s*(\S+),", block)
        remote_iface = re.search(r"Port ID \(outgoing port\):\s*(\S+)", block)
        if device_id and ip_addr:
            neighbors.append({
                "device_id": device_id.group(1),
                "ip": ip_addr.group(1),
                "platform": platform.group(1).strip() if platform else "unknown",
                "local_interface": local_iface.group(1) if local_iface else "unknown",
                "remote_interface": remote_iface.group(1) if remote_iface else "unknown",
            })
    return neighbors


def parse_lldp_neighbors(output: str) -> list[dict]:
    neighbors = []
    blocks = re.split(r"-{10,}|={10,}", output)
    for block in blocks:
        system_name = re.search(r"System Name:\s*(\S+)", block)
        ip_addr = re.search(r"(?:Management Address|IP):\s*(\d+\.\d+\.\d+\.\d+)", block)
        system_desc = re.search(r"System Description:\s*(.+)", block)
        local_iface = re.search(r"Local Intf:\s*(\S+)", block)
        remote_iface = re.search(r"Port id:\s*(\S+)", block)
        if system_name and ip_addr:
            neighbors.append({
                "device_id": system_name.group(1),
                "ip": ip_addr.group(1),
                "platform": system_desc.group(1).strip()[:40] if system_desc else "unknown",
                "local_interface": local_iface.group(1) if local_iface else "unknown",
                "remote_interface": remote_iface.group(1) if remote_iface else "unknown",
            })
    return neighbors


def query_neighbors(
    host: str, username: str, password: str, device_type: str, protocol: str
) -> list[dict]:
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "timeout": 15,
    }
    command = (
        "show cdp neighbors detail" if protocol == "cdp" else "show lldp neighbors detail"
    )
    try:
        with ConnectHandler(**params) as conn:
            output = conn.send_command(command, read_timeout=30)
        parser = parse_cdp_neighbors if protocol == "cdp" else parse_lldp_neighbors
        return parser(output)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", host)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", host)
    except Exception as exc:
        log.error("Error querying %s: %s", host, exc)
    return []


def crawl(
    seed_host: str,
    username: str,
    password: str,
    device_type: str,
    protocol: str,
    max_depth: int,
) -> list[dict]:
    edges = []
    visited_ips = {seed_host}
    queue = deque([(seed_host, seed_host, 0)])

    while queue:
        host, source_label, depth = queue.popleft()
        log.info("Querying %s (depth %d)", host, depth)
        neighbors = query_neighbors(host, username, password, device_type, protocol)
        for nbr in neighbors:
            edges.append({
                "source_host": source_label,
                "source_interface": nbr["local_interface"],
                "neighbor_device_id": nbr["device_id"],
                "neighbor_ip": nbr["ip"],
                "neighbor_interface": nbr["remote_interface"],
                "platform": nbr["platform"],
            })
            if depth < max_depth and nbr["ip"] not in visited_ips:
                visited_ips.add(nbr["ip"])
                queue.append((nbr["ip"], nbr["device_id"], depth + 1))

    return edges


def print_table(edges: list[dict]) -> None:
    if not edges:
        print("No neighbors discovered.")
        return
    header = (
        f"{'Source':<22} {'Src Intf':<16} {'Neighbor':<26} "
        f"{'Nbr IP':<16} {'Nbr Intf':<16} Platform"
    )
    print(header)
    print("-" * len(header))
    for e in edges:
        print(
            f"{e['source_host']:<22} {e['source_interface']:<16} "
            f"{e['neighbor_device_id']:<26} {e['neighbor_ip']:<16} "
            f"{e['neighbor_interface']:<16} {e['platform']}"
        )


def write_csv(edges: list[dict], path: str) -> None:
    fields = [
        "source_host", "source_interface", "neighbor_device_id",
        "neighbor_ip", "neighbor_interface", "platform",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(edges)
    log.info("Topology written to %s (%d rows)", path, len(edges))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Discover network topology via CDP/LLDP neighbor crawling."
    )
    parser.add_argument("--host", required=True, help="Seed device IP or hostname")
    parser.add_argument("--username", "-u", required=True, help="SSH username")
    parser.add_argument("--password", "-p", required=True, help="SSH password")
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
        help="Crawl depth: 0 = seed only, 1 = seed + neighbors (default: 1)",
    )
    parser.add_argument("--output", help="Write results to a CSV file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    edges = crawl(
        seed_host=args.host,
        username=args.username,
        password=args.password,
        device_type=args.device_type,
        protocol=args.protocol,
        max_depth=args.depth,
    )

    print_table(edges)

    if args.output:
        write_csv(edges, args.output)

    unique_devices = len({e["neighbor_ip"] for e in edges})
    log.info(
        "Discovery complete — %d adjacencies, %d unique neighbors",
        len(edges),
        unique_devices,
    )
    sys.exit(0 if edges else 1)


if __name__ == "__main__":
    main()