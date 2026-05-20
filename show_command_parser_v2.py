The task is fully specified with no design ambiguity — outputting the script directly as instructed.

"""
neighbor_map.py — CDP/LLDP Neighbor Topology Mapper

Connects to a network device via SSH and extracts CDP or LLDP neighbor
information, producing a structured topology summary useful for audits,
documentation, and change-impact analysis.

Usage:
    python neighbor_map.py -d 192.168.1.1 -u admin
    python neighbor_map.py -d 192.168.1.1 -u admin -p secret --protocol lldp
    python neighbor_map.py -d 192.168.1.1 -u admin --output json --device-type cisco_ios_xe

Prerequisites:
    pip install netmiko
    CDP or LLDP must be enabled on the target device.
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass
from getpass import getpass

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.WARNING)
log = logging.getLogger(__name__)


@dataclass
class Neighbor:
    device_id: str
    local_port: str
    remote_port: str
    platform: str = ""
    mgmt_address: str = ""
    capabilities: str = ""


def parse_cdp_neighbors(output: str) -> list[Neighbor]:
    neighbors = []
    for block in re.split(r"-{3,}", output):
        if not block.strip():
            continue
        device_id = re.search(r"Device ID:\s*(\S+)", block)
        local_port = re.search(r"Interface:\s*([^,]+),", block)
        remote_port = re.search(r"Port ID \(outgoing port\):\s*(.+)", block)
        platform = re.search(r"Platform:\s*([^,]+)", block)
        mgmt = re.search(r"(?:IP address|IPv4 Address):\s*(\S+)", block)
        caps = re.search(r"Capabilities:\s*(.+)", block)

        if not (device_id and local_port and remote_port):
            continue

        neighbors.append(Neighbor(
            device_id=device_id.group(1).strip(),
            local_port=local_port.group(1).strip(),
            remote_port=remote_port.group(1).strip(),
            platform=platform.group(1).strip() if platform else "",
            mgmt_address=mgmt.group(1).strip() if mgmt else "",
            capabilities=caps.group(1).strip() if caps else "",
        ))
    return neighbors


def parse_lldp_neighbors(output: str) -> list[Neighbor]:
    neighbors = []
    for block in re.split(r"(?=Local Intf:)", output):
        if not block.strip():
            continue
        local_port = re.search(r"Local Intf:\s*(\S+)", block)
        device_id = re.search(r"System Name:\s*(\S+)", block)
        remote_port = re.search(r"Port id:\s*(\S+)", block)
        platform = re.search(r"System Description:\s*(.+)", block)
        mgmt = re.search(r"Management Addresses[^\n]*\n\s*(\d+\.\d+\.\d+\.\d+)", block)
        caps = re.search(r"System Capabilities:\s*(.+)", block)

        if not (device_id and local_port and remote_port):
            continue

        neighbors.append(Neighbor(
            device_id=device_id.group(1).strip(),
            local_port=local_port.group(1).strip(),
            remote_port=remote_port.group(1).strip(),
            platform=platform.group(1).strip()[:60] if platform else "",
            mgmt_address=mgmt.group(1).strip() if mgmt else "",
            capabilities=caps.group(1).strip() if caps else "",
        ))
    return neighbors


def collect_neighbors(
    host: str,
    username: str,
    password: str,
    device_type: str,
    protocol: str,
) -> list[Neighbor]:
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
    }
    log.info("Connecting to %s", host)
    with ConnectHandler(**device) as conn:
        if protocol == "cdp":
            output = conn.send_command("show cdp neighbors detail")
            return parse_cdp_neighbors(output)
        output = conn.send_command("show lldp neighbors detail")
        return parse_lldp_neighbors(output)


def print_table(neighbors: list[Neighbor]) -> None:
    if not neighbors:
        print("No neighbors found.")
        return
    col = (30, 20, 20, 16)
    header = (
        f"{'Device ID':<{col[0]}} {'Local Port':<{col[1]}} "
        f"{'Remote Port':<{col[2]}} {'Mgmt IP':<{col[3]}} Platform"
    )
    print(header)
    print("-" * (sum(col) + 30))
    for n in neighbors:
        print(
            f"{n.device_id:<{col[0]}} {n.local_port:<{col[1]}} "
            f"{n.remote_port:<{col[2]}} {n.mgmt_address:<{col[3]}} {n.platform}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Map CDP/LLDP neighbors from a network device"
    )
    parser.add_argument("-d", "--device", required=True, help="Target device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument(
        "--protocol", choices=["cdp", "lldp"], default="cdp",
        help="Discovery protocol to query (default: cdp)",
    )
    parser.add_argument(
        "--output", choices=["table", "json"], default="table",
        help="Output format (default: table)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}@{args.device}: ")

    try:
        neighbors = collect_neighbors(
            host=args.device,
            username=args.username,
            password=password,
            device_type=args.device_type,
            protocol=args.protocol,
        )
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        return 1
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.device)
        return 1
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        return 1

    if args.output == "json":
        print(json.dumps([asdict(n) for n in neighbors], indent=2))
    else:
        print(f"\n{args.protocol.upper()} neighbors on {args.device} ({len(neighbors)} found)\n")
        print_table(neighbors)

    return 0


if __name__ == "__main__":
    sys.exit(main())