```python
"""
016_cdp_lldp_topology.py — CDP/LLDP Neighbor Topology Mapper

Purpose:
    Connect to a seed device, collect CDP and/or LLDP neighbor tables,
    and optionally recurse into discovered neighbors to build a full
    layer-2/layer-3 topology map. Outputs a structured JSON report
    and a human-readable summary.

Usage:
    python 016_cdp_lldp_topology.py --host 10.0.0.1 --username admin \
        --password secret --device-type cisco_ios --recurse --depth 2

Prerequisites:
    pip install netmiko
    CDP must be enabled on IOS/IOS-XE devices (default on most).
    LLDP must be enabled explicitly on many platforms.
"""

import argparse
import json
import logging
import sys
from collections import deque
from datetime import datetime

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)


def parse_cdp_neighbors(raw: str) -> list[dict]:
    neighbors = []
    current: dict = {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("Device ID:"):
            if current:
                neighbors.append(current)
            current = {"device_id": line.split("Device ID:", 1)[1].strip(), "protocol": "CDP"}
        elif line.startswith("IP address:") and current:
            current.setdefault("ip", line.split("IP address:", 1)[1].strip())
        elif line.startswith("Platform:") and current:
            parts = line.split(",", 1)
            current["platform"] = parts[0].replace("Platform:", "").strip()
            if len(parts) > 1:
                current["capabilities"] = parts[1].replace("Capabilities:", "").strip()
        elif line.startswith("Interface:") and current:
            parts = line.split(",", 1)
            current["local_intf"] = parts[0].replace("Interface:", "").strip()
            if len(parts) > 1:
                current["remote_intf"] = parts[1].replace("Port ID (outgoing port):", "").strip()
    if current:
        neighbors.append(current)
    return neighbors


def parse_lldp_neighbors(raw: str) -> list[dict]:
    neighbors = []
    current: dict = {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("System Name:"):
            if current:
                neighbors.append(current)
            current = {"device_id": line.split("System Name:", 1)[1].strip(), "protocol": "LLDP"}
        elif line.startswith("Management Address:") and current:
            current.setdefault("ip", line.split("Management Address:", 1)[1].strip())
        elif line.startswith("System Description:") and current:
            current["platform"] = line.split("System Description:", 1)[1].strip()[:60]
        elif line.startswith("Local Intf:") and current:
            current["local_intf"] = line.split("Local Intf:", 1)[1].strip()
        elif line.startswith("Port id:") and current:
            current["remote_intf"] = line.split("Port id:", 1)[1].strip()
    if current:
        neighbors.append(current)
    return neighbors


def collect_neighbors(host: str, creds: dict, prefer: str) -> tuple[str, list[dict]]:
    device = {"host": host, **creds}
    try:
        log.info("Connecting to %s (%s)", host, creds["device_type"])
        with ConnectHandler(**device) as conn:
            hostname = conn.find_prompt().replace("#", "").replace(">", "").strip()
            neighbors: list[dict] = []
            if prefer in ("cdp", "both"):
                try:
                    raw = conn.send_command("show cdp neighbors detail", read_timeout=30)
                    neighbors += parse_cdp_neighbors(raw)
                except Exception as exc:
                    log.debug("CDP unavailable on %s: %s", host, exc)
            if prefer in ("lldp", "both") and not neighbors:
                try:
                    raw = conn.send_command("show lldp neighbors detail", read_timeout=30)
                    neighbors += parse_lldp_neighbors(raw)
                except Exception as exc:
                    log.debug("LLDP unavailable on %s: %s", host, exc)
            return hostname, neighbors
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", host)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", host)
    except Exception as exc:
        log.error("Error connecting to %s: %s", host, exc)
    return host, []


def build_topology(seed: str, creds: dict, prefer: str, recurse: bool, max_depth: int) -> dict:
    topology: dict[str, dict] = {}
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(seed, 0)])

    while queue:
        host, depth = queue.popleft()
        if host in visited or depth > max_depth:
            continue
        visited.add(host)
        hostname, neighbors = collect_neighbors(host, creds, prefer)
        topology[hostname] = {"ip": host, "neighbors": neighbors, "depth": depth}
        log.info("%-20s → %d neighbor(s) found", hostname, len(neighbors))
        if recurse and depth < max_depth:
            for n in neighbors:
                nbr_ip = n.get("ip")
                if nbr_ip and nbr_ip not in visited:
                    queue.append((nbr_ip, depth + 1))

    return topology


def print_summary(topology: dict) -> None:
    print("\n" + "=" * 70)
    print(f"{'DEVICE':<25} {'IP':<18} {'NEIGHBOR':<25} {'LOCAL INTF':<16}")
    print("=" * 70)
    for hostname, data in sorted(topology.items()):
        ip = data["ip"]
        nbrs = data["neighbors"]
        if not nbrs:
            print(f"{hostname:<25} {ip:<18} {'(no neighbors)':<25}")
        for nbr in nbrs:
            print(
                f"{hostname:<25} {ip:<18} {nbr.get('device_id', '?'):<25} "
                f"{nbr.get('local_intf', '?'):<16}"
            )
    print("=" * 70)
    total_links = sum(len(d["neighbors"]) for d in topology.values())
    print(f"Devices: {len(topology)}  |  Links: {total_links}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CDP/LLDP neighbor topology mapper",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", required=True, help="Seed device IP or hostname")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--secret", default="", help="Enable secret (if required)")
    parser.add_argument("--device-type", default="cisco_ios", dest="device_type")
    parser.add_argument("--protocol", choices=["cdp", "lldp", "both"], default="cdp",
                        help="Neighbor discovery protocol")
    parser.add_argument("--recurse", action="store_true",
                        help="Recursively discover neighbors of neighbors")
    parser.add_argument("--depth", type=int, default=2,
                        help="Maximum recursion depth (only used with --recurse)")
    parser.add_argument("--output", metavar="FILE",
                        help="Write JSON report to this file")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    creds = {
        "device_type": args.device_type,
        "username": args.username,
        "password": args.password,
        "secret": args.secret,
    }
    depth = args.depth if args.recurse else 0
    topology = build_topology(args.host, creds, args.protocol, args.recurse, depth)

    if not topology:
        log.error("No data collected — check connectivity and credentials")
        sys.exit(1)

    print_summary(topology)

    report = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "seed": args.host,
        "protocol": args.protocol,
        "topology": topology,
    }
    if args.output:
        with open(args.output, "w") as fh:
            json.dump(report, fh, indent=2)
        log.info("Report written to %s", args.output)
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
```