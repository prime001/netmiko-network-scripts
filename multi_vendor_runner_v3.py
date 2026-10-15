```python
#!/usr/bin/env python3
"""
cdp_lldp_mapper.py - Network topology mapper via CDP/LLDP neighbor walks.

Purpose:
    Connects to a seed device, collects CDP or LLDP neighbor data, then
    recursively walks to each reachable neighbor up to a configurable hop
    depth. Produces an adjacency table and an optional Graphviz DOT file
    for visualization.

Usage:
    python cdp_lldp_mapper.py --host 10.0.0.1 --username admin --password secret
    python cdp_lldp_mapper.py --host 10.0.0.1 -u admin -p secret --depth 3
    python cdp_lldp_mapper.py --host 10.0.0.1 -u admin --protocol lldp --output topo.dot

Prerequisites:
    pip install netmiko
    CDP or LLDP must be enabled on target devices.
    SSH access required; all devices share the provided credentials.
    Neighbor IP addresses must be present in protocol output for recursion.
"""

import argparse
import getpass
import logging
import re
import sys
from collections import deque
from dataclasses import dataclass, field

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class Link:
    local_device: str
    local_intf: str
    remote_device: str
    remote_intf: str
    remote_ip: str = ""
    platform: str = ""


@dataclass
class DeviceNode:
    hostname: str
    ip: str
    links: list = field(default_factory=list)
    reachable: bool = True
    error: str = ""


def _normalize(name: str) -> str:
    return name.strip().split(".")[0].lower()


def parse_cdp_detail(output: str, local_device: str) -> list:
    links = []
    for entry in re.split(r"-{5,}", output):
        dev = re.search(r"Device ID:\s*(\S+)", entry)
        loc_if = re.search(r"Interface:\s*(\S+),", entry)
        rem_if = re.search(r"Port ID \(outgoing port\):\s*(\S+)", entry)
        if not (dev and loc_if and rem_if):
            continue
        ip_match = re.search(r"IP(?:v4)?\s+[Aa]ddress:\s*(\d[\d.]+)", entry)
        plat = re.search(r"Platform:\s*([^,\n]+)", entry)
        links.append(Link(
            local_device=local_device,
            local_intf=loc_if.group(1).rstrip(","),
            remote_device=_normalize(dev.group(1)),
            remote_intf=rem_if.group(1),
            remote_ip=ip_match.group(1) if ip_match else "",
            platform=plat.group(1).strip() if plat else "",
        ))
    return links


def parse_lldp_detail(output: str, local_device: str) -> list:
    links = []
    for entry in re.split(r"-{5,}|={5,}", output):
        sys_name = re.search(r"System Name:\s*(\S+)", entry, re.I)
        loc_if = re.search(r"Local\s+(?:Intf|Interface|Port[^:]*)?:\s*(\S+)", entry, re.I)
        port_id = re.search(r"Port(?:\s+id|\s+ID):\s*(\S+)", entry, re.I)
        if not (sys_name and loc_if and port_id):
            continue
        ip_match = re.search(r"(?:Management\s+Address(?:es)?|IP(?:v4)?)[:\s]+(\d[\d.]+)", entry, re.I)
        links.append(Link(
            local_device=local_device,
            local_intf=loc_if.group(1),
            remote_device=_normalize(sys_name.group(1)),
            remote_intf=port_id.group(1),
            remote_ip=ip_match.group(1) if ip_match else "",
        ))
    return links


def probe_device(host: str, username: str, password: str,
                 device_type: str, protocol: str) -> DeviceNode:
    node = DeviceNode(hostname=host, ip=host)
    params = dict(device_type=device_type, host=host, username=username,
                  password=password, timeout=15, conn_timeout=10)
    try:
        with ConnectHandler(**params) as conn:
            prompt = conn.find_prompt()
            node.hostname = re.sub(r"[>#].*$", "", prompt).strip().lower()
            if protocol == "cdp":
                out = conn.send_command("show cdp neighbors detail", read_timeout=30)
                node.links = parse_cdp_detail(out, node.hostname)
            else:
                out = conn.send_command("show lldp neighbors detail", read_timeout=30)
                node.links = parse_lldp_detail(out, node.hostname)
    except NetmikoAuthenticationException:
        node.reachable, node.error = False, "auth failed"
    except NetmikoTimeoutException:
        node.reachable, node.error = False, "timeout"
    except Exception as exc:
        node.reachable, node.error = False, str(exc)[:80]
    return node


def walk_topology(seed: str, username: str, password: str,
                  device_type: str, protocol: str, max_depth: int):
    visited_ips = {seed}
    visited_names: set = set()
    all_links: list[Link] = []
    nodes: dict[str, DeviceNode] = {}

    queue = deque([(seed, 0)])
    while queue:
        host, depth = queue.popleft()
        log.info("Probing %s at depth %d", host, depth)
        node = probe_device(host, username, password, device_type, protocol)
        nodes[host] = node

        if not node.reachable:
            log.warning("  %s — %s", host, node.error)
            continue

        log.info("  %s: %d link(s) found", node.hostname, len(node.links))
        visited_names.add(node.hostname)
        all_links.extend(node.links)

        if depth >= max_depth:
            continue

        for link in node.links:
            if not link.remote_ip:
                continue
            if link.remote_ip in visited_ips or link.remote_device in visited_names:
                continue
            visited_ips.add(link.remote_ip)
            queue.append((link.remote_ip, depth + 1))

    return all_links, nodes


def print_table(links: list[Link], nodes: dict):
    print("\n" + "=" * 84)
    print(f"{'LOCAL DEVICE':<20} {'LOCAL INTF':<18} {'REMOTE DEVICE':<20} "
          f"{'REMOTE INTF':<16} {'REMOTE IP'}")
    print("-" * 84)
    seen: set = set()
    for lk in links:
        key = frozenset([(lk.local_device, lk.local_intf), (lk.remote_device, lk.remote_intf)])
        if key in seen:
            continue
        seen.add(key)
        print(f"{lk.local_device:<20} {lk.local_intf:<18} {lk.remote_device:<20} "
              f"{lk.remote_intf:<16} {lk.remote_ip}")
    print("=" * 84)

    bad = [(ip, n) for ip, n in nodes.items() if not n.reachable]
    if bad:
        print(f"\nUnreachable ({len(bad)}):")
        for ip, n in bad:
            print(f"  {ip}: {n.error}")


def write_dot(links: list[Link], path: str):
    seen: set = set()
    lines = ['graph network_topology {', '  graph [overlap=false];', '  node [shape=box];']
    for lk in links:
        a, b = sorted([lk.local_device, lk.remote_device])
        edge = (a, b, lk.local_intf, lk.remote_intf)
        if edge in seen:
            continue
        seen.add(edge)
        lines.append(f'  "{a}" -- "{b}" [label="{lk.local_intf}--{lk.remote_intf}"];')
    lines.append("}")
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    log.info("DOT written to %s  (render: dot -Tpng %s -o topology.png)", path, path)


def parse_args():
    p = argparse.ArgumentParser(description="Map network topology via CDP/LLDP neighbor walks.")
    p.add_argument("--host", required=True, help="Seed device IP or hostname")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", help="Omit to prompt securely")
    p.add_argument("--device-type", default="cisco_ios",
                   help="Netmiko device type (default: cisco_ios)")
    p.add_argument("--protocol", choices=["cdp", "lldp"], default="cdp",
                   help="Neighbor protocol (default: cdp)")
    p.add_argument("--depth", type=int, default=2,
                   help="Max recursive hop depth (default: 2)")
    p.add_argument("--output", metavar="FILE", help="Write Graphviz DOT file to FILE")
    p.add_argument("--debug", action="store_true")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}: ")

    log.info("Starting %s walk from %s (max depth: %d)",
             args.protocol.upper(), args.host, args.depth)

    links, nodes = walk_topology(
        seed=args.host,
        username=args.username,
        password=password,
        device_type=args.device_type,
        protocol=args.protocol,
        max_depth=args.depth,
    )

    if not links:
        log.error("No neighbor links discovered.")
        sys.exit(1)

    print_table(links, nodes)

    if args.output:
        write_dot(links, args.output)

    reached = sum(1 for n in nodes.values() if n.reachable)
    log.info("Done: %d device(s) probed, %d link(s) mapped", reached, len(links))
```