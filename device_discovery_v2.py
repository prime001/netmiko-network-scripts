```python
"""
cdp_lldp_mapper.py - Network topology discovery via CDP/LLDP neighbor walks.

Purpose:
    Connects to a seed device, collects CDP and/or LLDP neighbor tables,
    and optionally recurses into discovered neighbors to build a full
    layer-2/layer-3 topology map. Outputs results as JSON or a human-
    readable adjacency table. Unlike IP-sweep discovery, this uses
    control-plane neighbor data already exchanged between devices.

Usage:
    python cdp_lldp_mapper.py --host 10.0.0.1 --username admin --password secret
    python cdp_lldp_mapper.py --host 10.0.0.1 -u admin -p secret --recurse --depth 3
    python cdp_lldp_mapper.py --host 10.0.0.1 -u admin -p secret --protocol lldp --json

Prerequisites:
    pip install netmiko
    CDP or LLDP must be enabled on target devices.
    Account needs at minimum read-only (show) access.
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
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def parse_cdp_neighbors(output):
    neighbors = []
    for block in re.split(r"-{10,}", output):
        if "Device ID" not in block:
            continue
        n = {}
        m = re.search(r"Device ID:\s*(\S+)", block)
        if m:
            n["device_id"] = m.group(1)
        m = re.search(r"IP address:\s*(\S+)", block, re.IGNORECASE)
        if m:
            n["mgmt_ip"] = m.group(1)
        m = re.search(r"Platform:\s*(.+?),", block)
        if m:
            n["platform"] = m.group(1).strip()
        m = re.search(r"Interface:\s*(\S+),\s+Port ID.*?:\s*(\S+)", block)
        if m:
            n["local_port"] = m.group(1)
            n["remote_port"] = m.group(2)
        m = re.search(r"Capabilities:\s*(.+)", block)
        if m:
            n["capabilities"] = m.group(1).strip()
        if n:
            neighbors.append(n)
    return neighbors


def parse_lldp_neighbors(output):
    neighbors = []
    for block in re.split(r"(?=Local Intf:)", output):
        if "System Name" not in block:
            continue
        n = {}
        m = re.search(r"Local Intf:\s*(\S+)", block)
        if m:
            n["local_port"] = m.group(1)
        m = re.search(r"System Name:\s*(\S+)", block)
        if m:
            n["device_id"] = m.group(1)
        m = re.search(r"Management Address:\s*(\S+)", block)
        if m:
            n["mgmt_ip"] = m.group(1)
        m = re.search(r"Port Description:\s*(\S+)", block)
        if m:
            n["remote_port"] = m.group(1)
        m = re.search(r"System Capabilities:\s*(.+)", block)
        if m:
            n["capabilities"] = m.group(1).strip()
        if n:
            neighbors.append(n)
    return neighbors


def collect_neighbors(host, username, password, device_type, protocol):
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "timeout": 20,
    }
    try:
        log.info("Connecting to %s", host)
        with ConnectHandler(**params) as conn:
            hostname = conn.find_prompt().rstrip("#>").strip()
            cdp_neighbors, lldp_neighbors = [], []
            if protocol in ("cdp", "both"):
                out = conn.send_command("show cdp neighbors detail", read_timeout=30)
                cdp_neighbors = parse_cdp_neighbors(out)
            if protocol in ("lldp", "both"):
                out = conn.send_command("show lldp neighbors detail", read_timeout=30)
                lldp_neighbors = parse_lldp_neighbors(out)
        deduped = {}
        for n in cdp_neighbors + lldp_neighbors:
            key = n.get("device_id") or n.get("mgmt_ip", "unknown")
            deduped.setdefault(key, n)
        return hostname, list(deduped.values())
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", host)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", host)
    except Exception as exc:
        log.error("Error on %s: %s", host, exc)
    return None, []


def walk_topology(seed, username, password, device_type, protocol, max_depth):
    topology = {}
    visited = {seed}
    queue = deque([(seed, 0)])

    while queue:
        host, depth = queue.popleft()
        hostname, neighbors = collect_neighbors(host, username, password, device_type, protocol)
        if hostname is None:
            continue
        topology[host] = {"hostname": hostname, "neighbors": neighbors, "depth": depth}
        log.info("%-20s (%s)  %d neighbor(s)", hostname, host, len(neighbors))
        if depth < max_depth:
            for n in neighbors:
                ip = n.get("mgmt_ip")
                if ip and ip not in visited:
                    visited.add(ip)
                    queue.append((ip, depth + 1))

    return topology


def print_table(topology):
    width = 72
    print(f"\n{'='*width}")
    print(f"{'NETWORK TOPOLOGY — CDP/LLDP MAP':^{width}}")
    print(f"{'='*width}")
    for ip, data in topology.items():
        indent = "  " * data["depth"]
        print(f"\n{indent}[{data['hostname']}] {ip}  (hop {data['depth']})")
        if not data["neighbors"]:
            print(f"{indent}  (no neighbors discovered)")
        for n in data["neighbors"]:
            dev = n.get("device_id", "unknown")
            mgmt = n.get("mgmt_ip", "no-ip")
            local = n.get("local_port", "?")
            remote = n.get("remote_port", "?")
            plat = n.get("platform", "")
            print(f"{indent}  ├─ {dev} ({mgmt})  {local} -> {remote}  {plat}")
    print(f"\n{'='*width}")
    print(f"Total devices discovered: {len(topology)}\n")


def build_parser():
    p = argparse.ArgumentParser(
        description="Map network topology by walking CDP/LLDP neighbor tables."
    )
    p.add_argument("--host", required=True, help="Seed device IP or hostname")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)
    p.add_argument("--device-type", default="cisco_ios",
                   help="Netmiko device type (default: cisco_ios)")
    p.add_argument("--protocol", choices=["cdp", "lldp", "both"], default="cdp",
                   help="Neighbor protocol to query (default: cdp)")
    p.add_argument("--recurse", action="store_true",
                   help="Recurse into discovered neighbors")
    p.add_argument("--depth", type=int, default=2,
                   help="Max hop depth when --recurse is set (default: 2)")
    p.add_argument("--json", action="store_true", dest="json_output",
                   help="Emit JSON instead of a human-readable table")
    p.add_argument("--debug", action="store_true")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    topology = walk_topology(
        args.host,
        args.username,
        args.password,
        args.device_type,
        args.protocol,
        args.depth if args.recurse else 0,
    )

    if not topology:
        log.error("No devices discovered. Check connectivity and credentials.")
        sys.exit(1)

    if args.json_output:
        print(json.dumps(topology, indent=2))
    else:
        print_table(topology)
```