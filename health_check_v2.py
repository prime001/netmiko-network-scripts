bgp_monitor.py - BGP Neighbor State Monitor

Connects to a Cisco IOS/IOS-XE/NX-OS device via SSH and reports the state
of all BGP neighbors. Flags any session not in Established state, making it
useful as a post-change check or scheduled alert.

Usage:
    python bgp_monitor.py -d 10.0.0.1 -u admin -p secret
    python bgp_monitor.py -d 10.0.0.1 -u admin --password-prompt
    python bgp_monitor.py -d 10.0.0.1 -u admin -p secret --vrf CUSTOMER_A
    python bgp_monitor.py -d 10.0.0.1 -u admin -p secret --fail-on-down

Prerequisites:
    pip install netmiko
"""

import argparse
import getpass
import logging
import re
import sys
from dataclasses import dataclass
from typing import List, Optional

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

SUPPORTED_DEVICE_TYPES = ["cisco_ios", "cisco_xe", "cisco_nxos"]


@dataclass
class BgpNeighbor:
    neighbor: str
    vrf: str
    asn: str
    state: str
    prefixes_received: str
    uptime: str


def parse_bgp_summary(output: str, vrf: str) -> List[BgpNeighbor]:
    """Parse 'show [ip] bgp [vrf X] summary' output into neighbor records."""
    neighbors = []
    # Matches neighbor table rows: IP v AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd
    pattern = re.compile(
        r"^(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)",
        re.MULTILINE,
    )
    for match in pattern.finditer(output):
        neighbor, asn, uptime, state_or_pfx = match.groups()
        if state_or_pfx.isdigit():
            state, prefixes = "Established", state_or_pfx
        else:
            state, prefixes = state_or_pfx, "0"
        neighbors.append(
            BgpNeighbor(
                neighbor=neighbor,
                vrf=vrf,
                asn=asn,
                state=state,
                prefixes_received=prefixes,
                uptime=uptime,
            )
        )
    return neighbors


def collect_bgp_neighbors(
    connection, vrf: Optional[str]
) -> List[BgpNeighbor]:
    """Run BGP summary command and return parsed neighbor list."""
    vrf_clause = f" vrf {vrf}" if vrf else ""
    for base in ("show bgp", "show ip bgp"):
        cmd = f"{base}{vrf_clause} summary"
        output = connection.send_command(cmd, read_timeout=30)
        if "% Invalid" not in output and "% BGP not active" not in output:
            break
        logger.debug("Command '%s' failed, trying fallback", cmd)
    else:
        logger.warning("BGP summary command not supported on this device")
        return []

    return parse_bgp_summary(output, vrf or "default")


def print_report(neighbors: List[BgpNeighbor], hostname: str) -> int:
    """Print formatted neighbor table. Returns count of non-Established sessions."""
    col = 65
    print(f"\nBGP Neighbor Report — {hostname}")
    print("-" * col)
    print(
        f"{'Neighbor':<18} {'VRF':<12} {'ASN':<8} {'State':<14} "
        f"{'Up/Down':<12} Pfx Rcvd"
    )
    print("-" * col)

    non_established = 0
    for nbr in sorted(neighbors, key=lambda x: (x.state != "Established", x.neighbor)):
        flag = "! " if nbr.state != "Established" else "  "
        print(
            f"{flag}{nbr.neighbor:<16} {nbr.vrf:<12} {nbr.asn:<8} "
            f"{nbr.state:<14} {nbr.uptime:<12} {nbr.prefixes_received}"
        )
        if nbr.state != "Established":
            non_established += 1

    print("-" * col)
    established = len(neighbors) - non_established
    print(
        f"Total: {len(neighbors)}  Established: {established}  "
        f"Non-established: {non_established}"
    )
    if non_established:
        print("! = session not Established")
    return non_established


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Report BGP neighbor states on Cisco IOS/IOS-XE/NX-OS."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password")
    parser.add_argument(
        "--password-prompt",
        action="store_true",
        help="Prompt for password interactively (overrides -p)",
    )
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=SUPPORTED_DEVICE_TYPES,
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--vrf", default=None, help="Limit check to a specific VRF")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--timeout", type=int, default=30, help="Connection timeout in seconds (default: 30)"
    )
    parser.add_argument(
        "--fail-on-down",
        action="store_true",
        help="Exit with code 1 if any session is not Established",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password
    if args.password_prompt or not password:
        password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": password,
        "port": args.port,
        "timeout": args.timeout,
    }

    logger.info("Connecting to %s (%s)", args.device, args.device_type)
    try:
        with ConnectHandler(**device_params) as conn:
            hostname = conn.find_prompt().strip("#> ")
            logger.info("Connected — hostname: %s", hostname)
            neighbors = collect_bgp_neighbors(conn, vrf=args.vrf)
    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(2)
    except NetmikoTimeoutException:
        logger.error("Connection timed out reaching %s", args.device)
        sys.exit(2)
    except Exception as exc:
        logger.error("Unexpected error: %s", exc)
        sys.exit(2)

    if not neighbors:
        logger.warning(
            "No BGP neighbors found on %s (VRF: %s)", hostname, args.vrf or "default"
        )
        sys.exit(0)

    non_established = print_report(neighbors, hostname)
    sys.exit(1 if (args.fail_on_down and non_established) else 0)