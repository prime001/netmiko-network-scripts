026_neighbor_topology_map.py — CDP/LLDP Neighbor Topology Walker

Connects to a seed device, harvests CDP or LLDP neighbor tables, then
recursively walks each discovered neighbor up to a configurable depth.
Produces an adjacency list suitable for import into a diagramming tool
or further processing.

Usage:
    python 026_neighbor_topology_map.py --host 10.0.0.1 --username admin \
        --password secret --protocol cdp --depth 2 --output topology.json

Prerequisites:
    pip install netmiko
    CDP or LLDP must be enabled on all target devices.
    SSH access required; credentials must be uniform across the fleet
    or supplied per-host via --inventory CSV (host,user,pass columns).
"""

import argparse
import csv
import json
import logging
import re
import sys
from collections import deque
from getpass import getpass

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

CDP_COMMAND = "show cdp neighbors detail"
LLDP_COMMAND = "show lldp neighbors detail"

CDP_ENTRY_RE = re.compile(
    r"Device ID:\s*(?P<device_id>\S+).*?"
    r"IP address:\s*(?P<ip>\S+).*?"
    r"Platform:\s*(?P<platform>[^\n,]+)",
    re.DOTALL,
)

LLDP_ENTRY_RE = re.compile(
    r"System Name:\s*(?P<device_id>\S+).*?"
    r"Management Addresses.*?IP:\s*(?P<ip>\d+\.\d+\.\d+\.\d+).*?"
    r"System Description.*?(?P<platform>Cisco[^\n]+|Juniper[^\n]+|\S[^\n]*)",
    re.DOTALL,
)


def parse_neighbors(output: str, protocol: str) -> list[dict]:
    pattern = CDP_ENTRY_RE if protocol == "cdp" else LLDP_ENTRY_RE
    neighbors = []
    for m in pattern.finditer(output):
        neighbors.append({
            "device_id": m.group("device_id").split(".")[0].upper(),
            "ip": m.group("ip"),
            "platform": m.group("platform").strip(),
        })
    return neighbors


def collect_neighbors(host: str, username: str, password: str,
                      device_type: str, protocol: str) -> list[dict]:
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "timeout": 15,
    }
    cmd = CDP_COMMAND if protocol == "cdp" else LLDP_COMMAND
    try:
        with ConnectHandler(**device) as conn:
            hostname = conn.find_prompt().rstrip("#>").upper()
            log.info("Connected to %s (%s)", hostname, host)
            output = conn.send_command(cmd, read_timeout=30)
        return hostname, parse_neighbors(output, protocol)
    except NetmikoAuthenticationException:
        log.error("Auth failed: %s", host)
    except NetmikoTimeoutException:
        log.error("Timeout: %s", host)
    except Exception as exc:
        log.error("Error on %s: %s", host, exc)
    return None, []


def load_inventory(path: str) -> dict[str, dict]:
    creds = {}
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            creds[row["host"]] = {"username": row["username"], "password": row["password"]}
    return creds


def walk_topology(seed: str, default_username: str, default_password: str,
                  inventory: dict, device_type: str, protocol: str,
                  max_depth: int) -> dict:
    adjacency: dict[str, list[dict]] = {}
    visited_ips: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(seed, 0)])
    visited_ips.add(seed)

    while queue:
        host, depth = queue.popleft()
        creds = inventory.get(host, {})
        username = creds.get("username", default_username)
        password = creds.get("password", default_password)

        hostname, neighbors = collect_neighbors(
            host, username, password, device_type, protocol
        )
        if hostname is None:
            continue

        adjacency[hostname] = neighbors
        log.info("  %s — %d neighbor(s) found", hostname, len(neighbors))

        if depth < max_depth:
            for nbr in neighbors:
                ip = nbr["ip"]
                if ip and ip not in visited_ips:
                    visited_ips.add(ip)
                    queue.append((ip, depth + 1))

    return adjacency


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Walk CDP/LLDP topology from a seed device.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--host", required=True, help="Seed device IP or hostname")
    p.add_argument("--username", default="admin", help="SSH username")
    p.add_argument("--password", help="SSH password (prompted if omitted)")
    p.add_argument(
        "--inventory",
        metavar="CSV",
        help="CSV with host,username,password columns for per-device creds",
    )
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        help="Netmiko device_type for all devices",
    )
    p.add_argument(
        "--protocol",
        choices=["cdp", "lldp"],
        default="cdp",
        help="Neighbor discovery protocol",
    )
    p.add_argument(
        "--depth",
        type=int,
        default=2,
        metavar="N",
        help="Maximum hops from seed (0 = seed only)",
    )
    p.add_argument("--output", metavar="FILE", help="Write JSON adjacency list to FILE")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}: ")
    inventory = load_inventory(args.inventory) if args.inventory else {}

    log.info("Starting %s walk from %s (depth=%d)", args.protocol.upper(), args.host, args.depth)
    topology = walk_topology(
        seed=args.host,
        default_username=args.username,
        default_password=password,
        inventory=inventory,
        device_type=args.device_type,
        protocol=args.protocol,
        max_depth=args.depth,
    )

    if not topology:
        log.error("No devices discovered — check seed connectivity and credentials.")
        sys.exit(1)

    log.info("Discovered %d device(s).", len(topology))
    payload = json.dumps(topology, indent=2)

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(payload)
        log.info("Topology written to %s", args.output)
    else:
        print(payload)