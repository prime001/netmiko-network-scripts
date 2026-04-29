```python
"""
006_cdp_lldp_discovery.py — Network topology discovery via CDP/LLDP neighbor crawl.

Purpose:
    Connects to a seed device, harvests CDP and LLDP neighbor tables, and
    optionally recurses to build a layer-2/layer-3 adjacency map of the network.
    Output is written to JSON (default) or CSV for import into inventory tools.

Usage:
    python 006_cdp_lldp_discovery.py --host 10.0.0.1 --username admin \
        --password secret --device-type cisco_ios --recurse --output topo.json

Prerequisites:
    pip install netmiko
    CDP or LLDP must be enabled on target devices.
    Credentials must be valid on all discovered neighbors when --recurse is used.
"""

import argparse
import csv
import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from typing import Optional

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class Neighbor:
    local_host: str
    local_port: str
    remote_host: str
    remote_ip: str
    remote_port: str
    platform: str
    protocol: str  # cdp | lldp


@dataclass
class DeviceNode:
    host: str
    hostname: str = ""
    platform: str = ""
    software: str = ""
    neighbors: list[Neighbor] = field(default_factory=list)
    error: str = ""


def connect(host: str, username: str, password: str, device_type: str, port: int = 22):
    return ConnectHandler(
        host=host,
        username=username,
        password=password,
        device_type=device_type,
        port=port,
        timeout=15,
    )


def get_device_info(conn) -> tuple[str, str, str]:
    raw = conn.send_command("show version", use_textfsm=True)
    if isinstance(raw, list) and raw:
        r = raw[0]
        return r.get("hostname", ""), r.get("hardware", [""])[0], r.get("version", "")
    return conn.find_prompt().strip("#>"), "", ""


def get_cdp_neighbors(conn, local_host: str) -> list[Neighbor]:
    neighbors = []
    raw = conn.send_command("show cdp neighbors detail", use_textfsm=True)
    if not isinstance(raw, list):
        return neighbors
    for entry in raw:
        neighbors.append(
            Neighbor(
                local_host=local_host,
                local_port=entry.get("local_port", ""),
                remote_host=entry.get("destination_host", ""),
                remote_ip=entry.get("management_ip", ""),
                remote_port=entry.get("remote_port", ""),
                platform=entry.get("platform", ""),
                protocol="cdp",
            )
        )
    return neighbors


def get_lldp_neighbors(conn, local_host: str) -> list[Neighbor]:
    neighbors = []
    raw = conn.send_command("show lldp neighbors detail", use_textfsm=True)
    if not isinstance(raw, list):
        return neighbors
    for entry in raw:
        neighbors.append(
            Neighbor(
                local_host=local_host,
                local_port=entry.get("local_interface", ""),
                remote_host=entry.get("neighbor", ""),
                remote_ip=entry.get("management_address", ""),
                remote_port=entry.get("neighbor_interface", ""),
                platform=entry.get("system_description", ""),
                protocol="lldp",
            )
        )
    return neighbors


def discover(
    host: str,
    username: str,
    password: str,
    device_type: str,
    port: int,
    recurse: bool,
    visited: Optional[set] = None,
) -> list[DeviceNode]:
    if visited is None:
        visited = set()
    if host in visited:
        return []
    visited.add(host)

    node = DeviceNode(host=host)
    results = [node]

    try:
        log.info("Connecting to %s", host)
        with connect(host, username, password, device_type, port) as conn:
            node.hostname, node.platform, node.software = get_device_info(conn)
            log.info("  %s — %s %s", node.hostname or host, node.platform, node.software)

            cdp = get_cdp_neighbors(conn, node.hostname or host)
            lldp = get_lldp_neighbors(conn, node.hostname or host)
            node.neighbors = cdp + lldp
            log.info("  Found %d neighbor(s) (CDP:%d LLDP:%d)", len(node.neighbors), len(cdp), len(lldp))

    except NetmikoAuthenticationException:
        node.error = "auth_failed"
        log.error("Auth failed for %s", host)
        return results
    except NetmikoTimeoutException:
        node.error = "timeout"
        log.error("Timeout connecting to %s", host)
        return results
    except Exception as exc:
        node.error = str(exc)
        log.error("Error on %s: %s", host, exc)
        return results

    if recurse:
        for nbr in node.neighbors:
            if nbr.remote_ip and nbr.remote_ip not in visited:
                results.extend(
                    discover(nbr.remote_ip, username, password, device_type, port, recurse, visited)
                )

    return results


def write_json(nodes: list[DeviceNode], path: str) -> None:
    with open(path, "w") as fh:
        json.dump([asdict(n) for n in nodes], fh, indent=2)
    log.info("Wrote JSON to %s", path)


def write_csv(nodes: list[DeviceNode], path: str) -> None:
    rows = []
    for node in nodes:
        if not node.neighbors:
            rows.append({"device": node.host, "hostname": node.hostname,
                         "platform": node.platform, "software": node.software,
                         "local_port": "", "remote_host": "", "remote_ip": "",
                         "remote_port": "", "protocol": "", "error": node.error})
        for nbr in node.neighbors:
            rows.append({"device": node.host, "hostname": node.hostname,
                         "platform": node.platform, "software": node.software,
                         "local_port": nbr.local_port, "remote_host": nbr.remote_host,
                         "remote_ip": nbr.remote_ip, "remote_port": nbr.remote_port,
                         "protocol": nbr.protocol, "error": node.error})
    if not rows:
        return
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    log.info("Wrote CSV to %s", path)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Discover network topology via CDP/LLDP neighbor crawl."
    )
    p.add_argument("--host", required=True, help="Seed device IP or hostname")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--device-type", default="cisco_ios",
                   help="Netmiko device_type (default: cisco_ios)")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--recurse", action="store_true",
                   help="Follow neighbors recursively to map full topology")
    p.add_argument("--output", default="topology.json",
                   help="Output file path (.json or .csv)")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    nodes = discover(
        host=args.host,
        username=args.username,
        password=args.password,
        device_type=args.device_type,
        port=args.port,
        recurse=args.recurse,
    )

    log.info("Discovery complete: %d device(s) found", len(nodes))

    if args.output.endswith(".csv"):
        write_csv(nodes, args.output)
    else:
        write_json(nodes, args.output)

    errors = [n for n in nodes if n.error]
    if errors:
        log.warning("%d device(s) had errors: %s", len(errors),
                    ", ".join(f"{n.host}({n.error})" for n in errors))
        sys.exit(1)
```