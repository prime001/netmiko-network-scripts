The write is being blocked by permissions. Here's the complete script — copy it directly to your repo:

```python
"""
CDP/LLDP Neighbor Topology Mapper
==================================
Connects to one or more seed devices and walks CDP/LLDP neighbor tables to
build a layer-2 topology map.  Useful for auditing undocumented networks or
verifying that the physical topology matches the intended design.

Usage:
    python cdp_lldp_topology.py -d 192.168.1.1 -u admin -p secret
    python cdp_lldp_topology.py -d 192.168.1.1 -u admin -p secret --hops 2
    python cdp_lldp_topology.py -d 192.168.1.1 -u admin -p secret --protocol lldp --out topology.csv

Prerequisites:
    pip install netmiko
    Device must have CDP or LLDP enabled and credentials must have read access.
"""

import argparse
import csv
import logging
import sys
from collections import deque
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def get_cdp_neighbors(conn):
    output = conn.send_command("show cdp neighbors detail")
    neighbors = []
    current = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Device ID:"):
            if current:
                neighbors.append(current)
            current = {"device_id": line.split("Device ID:")[-1].strip()}
        elif line.startswith("IP address:") and "mgmt_ip" not in current:
            current["mgmt_ip"] = line.split("IP address:")[-1].strip()
        elif line.startswith("Platform:"):
            parts = line.split(",")
            current["platform"] = parts[0].split("Platform:")[-1].strip()
            if len(parts) > 1:
                current["capabilities"] = parts[1].split("Capabilities:")[-1].strip()
        elif line.startswith("Interface:"):
            parts = line.split(",")
            current["local_intf"] = parts[0].split("Interface:")[-1].strip()
            if len(parts) > 1:
                current["remote_intf"] = parts[1].split("Port ID")[-1].lstrip(" :(").strip()
    if current:
        neighbors.append(current)
    return neighbors


def get_lldp_neighbors(conn):
    output = conn.send_command("show lldp neighbors detail")
    neighbors = []
    current = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Local Intf:"):
            if current:
                neighbors.append(current)
            current = {"local_intf": line.split("Local Intf:")[-1].strip()}
        elif line.startswith("System Name:"):
            current["device_id"] = line.split("System Name:")[-1].strip()
        elif line.startswith("IP:") and "mgmt_ip" not in current:
            current["mgmt_ip"] = line.split("IP:")[-1].strip()
        elif line.startswith("Port id:"):
            current["remote_intf"] = line.split("Port id:")[-1].strip()
        elif line.startswith("System Capabilities:"):
            current["capabilities"] = line.split("System Capabilities:")[-1].strip()
    if current:
        neighbors.append(current)
    return neighbors


def connect(host, username, password, device_type):
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "timeout": 15,
    }
    return ConnectHandler(**params)


def walk_topology(seed, username, password, device_type, protocol, max_hops):
    """BFS walk from seed device; returns list of edge dicts."""
    edges = []
    visited = set()
    queue = deque([(seed, 0)])

    while queue:
        host, depth = queue.popleft()
        if host in visited or depth > max_hops:
            continue
        visited.add(host)

        log.info("Connecting to %s (hop %d)", host, depth)
        try:
            conn = connect(host, username, password, device_type)
        except AuthenticationException:
            log.error("Auth failed for %s — skipping", host)
            continue
        except NetmikoTimeoutException:
            log.error("Timeout connecting to %s — skipping", host)
            continue
        except Exception as exc:
            log.error("Cannot reach %s: %s — skipping", host, exc)
            continue

        try:
            neighbors = get_cdp_neighbors(conn) if protocol == "cdp" else get_lldp_neighbors(conn)
        finally:
            conn.disconnect()

        log.info("  %d neighbor(s) found on %s", len(neighbors), host)
        for nbr in neighbors:
            edges.append({"source": host, **nbr})
            mgmt = nbr.get("mgmt_ip")
            if mgmt and mgmt not in visited:
                queue.append((mgmt, depth + 1))

    return edges


def print_table(edges):
    header = f"{'Source':<18} {'Neighbor':<24} {'Local Intf':<20} {'Remote Intf':<20} {'Mgmt IP':<16}"
    print(header)
    print("-" * len(header))
    for e in edges:
        print(
            f"{e.get('source',''):<18} "
            f"{e.get('device_id',''):<24} "
            f"{e.get('local_intf',''):<20} "
            f"{e.get('remote_intf',''):<20} "
            f"{e.get('mgmt_ip',''):<16}"
        )


def write_csv(edges, path):
    fields = ["source", "device_id", "local_intf", "remote_intf", "mgmt_ip", "platform", "capabilities"]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(edges)
    log.info("Topology written to %s", path)


def parse_args():
    parser = argparse.ArgumentParser(description="CDP/LLDP topology mapper")
    parser.add_argument("-d", "--device", required=True, help="Seed device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument("-t", "--device-type", default="cisco_ios",
                        help="Netmiko device type (default: cisco_ios)")
    parser.add_argument("--protocol", choices=["cdp", "lldp"], default="cdp",
                        help="Neighbor protocol to query (default: cdp)")
    parser.add_argument("--hops", type=int, default=1,
                        help="Maximum BFS hops from seed (default: 1; 0 = seed only)")
    parser.add_argument("--out", default=None, help="Optional CSV output file path")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    password = args.password or getpass("SSH password: ")

    edges = walk_topology(
        seed=args.device,
        username=args.username,
        password=password,
        device_type=args.device_type,
        protocol=args.protocol,
        max_hops=args.hops,
    )

    if not edges:
        log.warning("No neighbor data collected.")
        sys.exit(1)

    print_table(edges)

    if args.out:
        write_csv(edges, args.out)
```

**What this does and why it's distinct from the existing `device_discovery*.py` scripts:**

- Those scripts typically do IP-range scanning or SNMP-based reachability checks. This one does **protocol-driven topology walking** — it interrogates the device's CDP or LLDP tables and optionally hops to discovered neighbors (BFS up to `--hops` depth).
- Practical use: drop it on an unfamiliar network with one known device and `--hops 3` to map what's physically connected, which interfaces link where, and what platforms are in the path.
- Outputs a formatted table to stdout and optionally a CSV for import into Visio/draw.io/NetBox.