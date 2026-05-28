BGP Neighbor State Monitor

Connects to a router and checks all BGP neighbor states, reporting peer uptime,
prefix counts, and AS numbers. Exits non-zero if any peer is not Established,
making it suitable for use in monitoring pipelines, cron jobs, and alerting hooks.

Usage:
    python bgp_neighbor_monitor.py -d 192.168.1.1 -u admin -p secret
    python bgp_neighbor_monitor.py -d 10.0.0.1 -u admin \
        --device-type cisco_xe --min-prefixes 100 --expected-peers 4

Exit codes:
    0 — all peers Established, prefix counts above threshold
    1 — one or more peers degraded or threshold violation
    2 — connection / auth failure

Prerequisites:
    pip install netmiko
"""

import argparse
import getpass
import logging
import re
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.WARNING)
logger = logging.getLogger(__name__)


@dataclass
class BgpPeer:
    neighbor: str
    as_number: str
    state: str
    uptime: str
    prefixes_received: int


def _parse_ios_style(output: str) -> List[BgpPeer]:
    """Parse IOS / IOS-XE / IOS-XR BGP summary table."""
    peers = []
    pattern = re.compile(
        r"^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+"  # neighbor IP
        r"\d+\s+"          # BGP version
        r"(\d+)\s+"        # remote AS
        r"\d+\s+"          # MsgRcvd
        r"\d+\s+"          # MsgSent
        r"\d+\s+"          # TblVer
        r"\d+\s+"          # InQ
        r"\d+\s+"          # OutQ
        r"(\S+)\s+"        # Up/Down
        r"(\S+)$",         # State or PfxRcd
        re.MULTILINE,
    )
    for m in pattern.finditer(output):
        neighbor, asn, uptime, state_or_pfx = m.groups()
        try:
            pfx = int(state_or_pfx)
            state = "Established"
        except ValueError:
            pfx = 0
            state = state_or_pfx
        peers.append(BgpPeer(neighbor, asn, state, uptime, pfx))
    return peers


def _parse_eos_style(output: str) -> List[BgpPeer]:
    """Parse Arista EOS BGP summary table."""
    peers = []
    pattern = re.compile(
        r"^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+"
        r"(\d+)\s+"        # AS
        r"\d+\s+\d+\s+"    # MsgRcvd / MsgSent
        r"\S+\s+\S+\s+"    # InQ / OutQ
        r"(\S+)\s+"        # Up/Down
        r"(\w+)\s+"        # State
        r"(\d+)",          # PfxRcd
        re.MULTILINE,
    )
    for m in pattern.finditer(output):
        neighbor, asn, uptime, state, pfx = m.groups()
        peers.append(BgpPeer(neighbor, asn, state, uptime, int(pfx)))
    return peers


_COMMANDS = {
    "cisco_ios": "show ip bgp summary",
    "cisco_xe": "show ip bgp summary",
    "cisco_xr": "show bgp ipv4 unicast summary",
    "arista_eos": "show ip bgp summary",
}

_PARSERS = {
    "cisco_ios": _parse_ios_style,
    "cisco_xe": _parse_ios_style,
    "cisco_xr": _parse_ios_style,
    "arista_eos": _parse_eos_style,
}


def collect_bgp_state(
    device_params: dict,
    device_type: str,
    min_prefixes: int,
    expected_peers: Optional[int],
    verbose: bool,
) -> Tuple[List[BgpPeer], List[str]]:
    command = _COMMANDS.get(device_type, "show ip bgp summary")
    parser = _PARSERS.get(device_type, _parse_ios_style)

    logger.info("Connecting to %s", device_params["host"])
    with ConnectHandler(**device_params) as conn:
        output = conn.send_command(command, read_timeout=30)

    if verbose:
        print(f"\n--- raw output ---\n{output}\n--- end raw ---\n")

    peers = parser(output)
    alerts: List[str] = []

    if expected_peers is not None and len(peers) != expected_peers:
        alerts.append(f"Expected {expected_peers} peers, found {len(peers)}")

    for peer in peers:
        if peer.state != "Established":
            alerts.append(f"Peer {peer.neighbor} AS{peer.as_number} is {peer.state}")
        elif peer.prefixes_received < min_prefixes:
            alerts.append(
                f"Peer {peer.neighbor} AS{peer.as_number}: "
                f"{peer.prefixes_received} prefixes < minimum {min_prefixes}"
            )

    return peers, alerts


def print_report(peers: List[BgpPeer], alerts: List[str], host: str) -> None:
    established = sum(1 for p in peers if p.state == "Established")
    status = "OK" if not alerts else "DEGRADED"

    print(f"\nBGP Neighbors — {host}  [{status}]")
    print(f"{'Neighbor':<22} {'AS':<8} {'State':<14} {'Uptime':<14} PfxRcd")
    print("─" * 68)
    for p in peers:
        marker = "  " if p.state == "Established" else "! "
        print(
            f"{marker}{p.neighbor:<20} {p.as_number:<8} "
            f"{p.state:<14} {p.uptime:<14} {p.prefixes_received}"
        )
    print(f"\n{established}/{len(peers)} peers Established")

    if alerts:
        print("\nAlerts:")
        for alert in alerts:
            print(f"  [!] {alert}")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Monitor BGP neighbor states and prefix counts via SSH."
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    p.add_argument(
        "-t", "--device-type",
        default="cisco_ios",
        choices=list(_COMMANDS.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=15, help="Connect timeout seconds")
    p.add_argument(
        "--min-prefixes", type=int, default=0, metavar="N",
        help="Alert if an Established peer has fewer than N received prefixes",
    )
    p.add_argument(
        "--expected-peers", type=int, metavar="N",
        help="Alert if total peer count differs from N",
    )
    p.add_argument("--verbose", "-v", action="store_true", help="Print raw device output")
    return p


if __name__ == "__main__":
    args = build_arg_parser().parse_args()
    password = args.password or getpass.getpass(f"Password for {args.username}@{args.device}: ")

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": password,
        "port": args.port,
        "timeout": args.timeout,
    }

    try:
        peers, alerts = collect_bgp_state(
            device_params=device_params,
            device_type=args.device_type,
            min_prefixes=args.min_prefixes,
            expected_peers=args.expected_peers,
            verbose=args.verbose,
        )
    except NetmikoAuthenticationException:
        print(f"ERROR: Authentication failed for {args.username}@{args.device}", file=sys.stderr)
        sys.exit(2)
    except NetmikoTimeoutException:
        print(f"ERROR: Connection timed out to {args.device}:{args.port}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        logger.debug("Exception detail", exc_info=True)
        sys.exit(2)

    print_report(peers, alerts, args.device)
    sys.exit(1 if alerts else 0)