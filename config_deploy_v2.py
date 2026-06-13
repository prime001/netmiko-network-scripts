BGP Session Monitor — netmiko network automation script.

Purpose:
    Connect to a router and audit BGP neighbor sessions. Reports session
    state, uptime, and received prefix counts. Flags any neighbor not in
    Established state and optionally alerts when prefix counts fall below
    a configurable threshold.

Usage:
    python bgp_monitor.py -d 192.168.1.1 -u admin -p secret
    python bgp_monitor.py -d 10.0.0.1 -u admin --device-type cisco_ios_xe
    python bgp_monitor.py -d 10.0.0.1 -u admin --prefix-threshold 100 --json

Prerequisites:
    pip install netmiko
    SSH access to a router with BGP configured.
    Supported device types: cisco_ios, cisco_ios_xe, cisco_xr, cisco_nxos
"""

import argparse
import getpass
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass
from typing import List, Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class BgpNeighbor:
    neighbor: str
    as_number: str
    state: str
    uptime: str
    prefixes_received: int
    msg_received: int
    msg_sent: int


def parse_bgp_summary(output: str) -> List[BgpNeighbor]:
    """Parse IOS/IOS-XE/NX-OS 'show bgp summary' neighbor table lines."""
    neighbors = []
    # Matches: neighbor, version, AS, MsgRcvd, MsgSent, TblVer, InQ, OutQ, Up/Down, State/PfxRcd
    pattern = re.compile(
        r'^(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)\s+'
        r'\d+\s+'
        r'(\d+)\s+'
        r'(\d+)\s+'
        r'(\d+)\s+'
        r'\d+\s+\d+\s+\d+\s+'
        r'(\S+)\s+'
        r'(\S+)',
        re.MULTILINE,
    )
    for m in pattern.finditer(output):
        neighbor_ip, asn, msg_rcvd, msg_sent, uptime, state_or_pfx = m.groups()
        try:
            pfx = int(state_or_pfx)
            state = "Established"
        except ValueError:
            pfx = 0
            state = state_or_pfx

        neighbors.append(
            BgpNeighbor(
                neighbor=neighbor_ip,
                as_number=asn,
                state=state,
                uptime=uptime,
                prefixes_received=pfx,
                msg_received=int(msg_rcvd),
                msg_sent=int(msg_sent),
            )
        )
    return neighbors


def collect_bgp_output(connection, device_type: str) -> str:
    commands = {
        "cisco_xr": "show bgp summary",
        "cisco_ios": "show bgp ipv4 unicast summary",
        "cisco_ios_xe": "show bgp ipv4 unicast summary",
        "cisco_nxos": "show bgp ipv4 unicast summary",
    }
    cmd = commands.get(device_type, "show bgp summary")
    logger.info("Running: %s", cmd)
    return connection.send_command(cmd)


def print_report(neighbors: List[BgpNeighbor], threshold: Optional[int]) -> None:
    header = (
        f"{'Neighbor':<22} {'AS':<8} {'State':<14} {'Uptime':<12}"
        f" {'Pfx Rcvd':>9} {'Msg Rcvd':>9} {'Msg Sent':>9}"
    )
    print(header)
    print("-" * len(header))

    alerts = []
    for n in neighbors:
        flag = ""
        if n.state != "Established":
            flag = " (!)"
            alerts.append(f"Session DOWN: {n.neighbor} AS{n.as_number} state={n.state}")
        elif threshold is not None and n.prefixes_received < threshold:
            flag = " (!)"
            alerts.append(
                f"Low prefixes: {n.neighbor} AS{n.as_number}"
                f" received={n.prefixes_received} threshold={threshold}"
            )
        print(
            f"{n.neighbor:<22} {n.as_number:<8} {n.state:<14} {n.uptime:<12}"
            f" {n.prefixes_received:>9} {n.msg_received:>9} {n.msg_sent:>9}{flag}"
        )

    if alerts:
        print("\nALERTS:")
        for alert in alerts:
            print(f"  * {alert}")
    else:
        print("\nAll BGP sessions OK.")


def main():
    parser = argparse.ArgumentParser(
        description="Audit BGP neighbor sessions on a router via SSH."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=["cisco_ios", "cisco_ios_xe", "cisco_xr", "cisco_nxos"],
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--prefix-threshold",
        type=int,
        metavar="N",
        help="Alert when received prefix count falls below N",
    )
    parser.add_argument(
        "--json", action="store_true", dest="json_output", help="Output results as JSON"
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.device}: "
    )

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": password,
        "port": args.port,
    }

    try:
        logger.info("Connecting to %s", args.device)
        with ConnectHandler(**device_params) as conn:
            raw_output = collect_bgp_output(conn, args.device_type)
    except NetmikoAuthenticationException:
        print(f"ERROR: Authentication failed for {args.username}@{args.device}", file=sys.stderr)
        sys.exit(1)
    except NetmikoTimeoutException:
        print(f"ERROR: Connection timed out to {args.device}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    neighbors = parse_bgp_summary(raw_output)

    if not neighbors:
        print("No BGP neighbors found or output could not be parsed.", file=sys.stderr)
        print("Raw output:\n", raw_output, file=sys.stderr)
        sys.exit(2)

    if args.json_output:
        result = {
            "device": args.device,
            "neighbor_count": len(neighbors),
            "neighbors": [asdict(n) for n in neighbors],
        }
        print(json.dumps(result, indent=2))
    else:
        print(f"\nBGP Summary — {args.device}\n")
        print_report(neighbors, args.prefix_threshold)

    # Exit 3 signals monitoring systems that actionable sessions were found
    non_established = [n for n in neighbors if n.state != "Established"]
    if non_established:
        sys.exit(3)


if __name__ == "__main__":
    main()