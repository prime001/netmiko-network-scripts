bgp_health_check.py - BGP Neighbor Session Auditor

Purpose:
    Connects to a network device via SSH and audits all BGP neighbor
    sessions. Flags neighbors not in Established state, sessions that
    reset recently (uptime below a configurable threshold), and neighbors
    approaching a prefix-count warning threshold.

Usage:
    python bgp_health_check.py --host 192.168.1.1 --username admin \
        --password secret --device-type cisco_ios

    python bgp_health_check.py --host 10.0.0.1 --username admin \
        --password secret --device-type cisco_xr \
        --reset-threshold 1800 --prefix-warning 750

Prerequisites:
    pip install netmiko
    SSH access with at least read-only / privilege-1 credentials.
    BGP must be configured on the target device.

Exit codes:
    0 - All neighbors healthy
    1 - One or more neighbors down or recently reset
    2 - Connection / authentication failure
"""

import argparse
import logging
import re
import sys
from dataclasses import dataclass
from typing import Dict, List

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)


@dataclass
class BgpNeighbor:
    address: str
    remote_as: str
    uptime: str
    state: str
    prefixes_received: int
    msg_received: int
    msg_sent: int


def parse_ios_bgp_summary(output: str) -> List[BgpNeighbor]:
    """Parse 'show ip bgp summary' for IOS, IOS-XE, and NX-OS."""
    neighbors: List[BgpNeighbor] = []
    in_table = False
    for line in output.splitlines():
        if "State/PfxRcd" in line or "State/Pfx" in line:
            in_table = True
            continue
        if not in_table:
            continue
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            state_field = parts[9]
            try:
                prefixes = int(state_field)
                state = "Established"
            except ValueError:
                prefixes = 0
                state = state_field
            neighbors.append(BgpNeighbor(
                address=parts[0],
                remote_as=parts[2],
                uptime=parts[8],
                state=state,
                prefixes_received=prefixes,
                msg_received=int(parts[3]),
                msg_sent=int(parts[4]),
            ))
        except (IndexError, ValueError):
            continue
    return neighbors


def parse_xr_bgp_summary(output: str) -> List[BgpNeighbor]:
    """Parse 'show bgp summary' for IOS-XR."""
    neighbors: List[BgpNeighbor] = []
    in_table = False
    for line in output.splitlines():
        if re.search(r"Neighbor\s+Spk\s+AS\s+MsgRcvd", line):
            in_table = True
            continue
        if not in_table:
            continue
        parts = line.split()
        if len(parts) < 9:
            continue
        try:
            state_field = parts[8]
            try:
                prefixes = int(state_field)
                state = "Established"
            except ValueError:
                prefixes = 0
                state = state_field
            neighbors.append(BgpNeighbor(
                address=parts[0],
                remote_as=parts[2],
                uptime=parts[7],
                state=state,
                prefixes_received=prefixes,
                msg_received=int(parts[4]),
                msg_sent=int(parts[5]),
            ))
        except (IndexError, ValueError):
            continue
    return neighbors


def uptime_seconds(uptime: str) -> int:
    """Convert IOS uptime string to seconds; return -1 if unparseable."""
    m = re.match(r"^(\d+):(\d+):(\d+)$", uptime)
    if m:
        return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))
    m = re.match(r"^(\d+)d(\d+)h$", uptime)
    if m:
        return int(m.group(1)) * 86400 + int(m.group(2)) * 3600
    return -1


def audit_neighbors(
    neighbors: List[BgpNeighbor],
    prefix_warning: int,
    reset_threshold: int,
) -> Dict[str, List[BgpNeighbor]]:
    buckets: Dict[str, List[BgpNeighbor]] = {
        "down": [], "recent_reset": [], "prefix_warning": [], "ok": []
    }
    for n in neighbors:
        if n.state != "Established":
            buckets["down"].append(n)
            continue
        secs = uptime_seconds(n.uptime)
        recently_reset = 0 <= secs < reset_threshold
        if recently_reset:
            buckets["recent_reset"].append(n)
        if n.prefixes_received >= prefix_warning:
            buckets["prefix_warning"].append(n)
        if not recently_reset and n.prefixes_received < prefix_warning:
            buckets["ok"].append(n)
    return buckets


def print_report(host: str, neighbors: List[BgpNeighbor], audit: Dict) -> int:
    sep = "=" * 62
    print(f"\n{sep}")
    print(f"  BGP Health Report  |  {host}  |  {len(neighbors)} neighbor(s)")
    print(sep)

    exit_code = 0

    if audit["down"]:
        exit_code = 1
        print(f"\n[CRITICAL]  {len(audit['down'])} session(s) not Established:")
        for n in audit["down"]:
            print(f"  {n.address:<22} AS {n.remote_as:<8} State: {n.state}")

    if audit["recent_reset"]:
        exit_code = 1
        print(f"\n[WARNING]   {len(audit['recent_reset'])} session(s) recently reset:")
        for n in audit["recent_reset"]:
            print(f"  {n.address:<22} AS {n.remote_as:<8} Uptime: {n.uptime}")

    if audit["prefix_warning"]:
        print(f"\n[WARNING]   {len(audit['prefix_warning'])} session(s) near prefix limit:")
        for n in audit["prefix_warning"]:
            print(f"  {n.address:<22} AS {n.remote_as:<8} Prefixes: {n.prefixes_received}")

    ok_count = len(audit["ok"])
    if ok_count:
        print(f"\n[OK]        {ok_count} session(s) healthy")

    print(f"\n{sep}\n")
    return exit_code


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit BGP neighbor sessions on a Cisco device."
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=["cisco_ios", "cisco_xr", "cisco_nxos"],
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument(
        "--reset-threshold",
        type=int,
        default=3600,
        metavar="SECONDS",
        help="Warn when session uptime is below this value (default: 3600)",
    )
    parser.add_argument(
        "--prefix-warning",
        type=int,
        default=500,
        metavar="COUNT",
        help="Warn when received prefixes exceed this value (default: 500)",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    bgp_cmd = "show bgp summary" if args.device_type == "cisco_xr" else "show ip bgp summary"
    parse_fn = parse_xr_bgp_summary if args.device_type == "cisco_xr" else parse_ios_bgp_summary

    logger.info("Connecting to %s (%s)", args.host, args.device_type)
    try:
        with ConnectHandler(
            device_type=args.device_type,
            host=args.host,
            username=args.username,
            password=args.password,
            port=args.port,
        ) as conn:
            logger.info("Connected — retrieving BGP summary")
            output = conn.send_command(bgp_cmd)
    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        return 2
    except NetmikoTimeoutException:
        logger.error("Connection to %s timed out", args.host)
        return 2
    except Exception as exc:
        logger.error("Connection error: %s", exc)
        return 2

    neighbors = parse_fn(output)
    if not neighbors:
        logger.warning("No BGP neighbors parsed — verify BGP is configured and output format")
        logger.debug("Raw output:\n%s", output)
        return 0

    audit = audit_neighbors(neighbors, args.prefix_warning, args.reset_threshold)
    return print_report(args.host, neighbors, audit)


if __name__ == "__main__":
    sys.exit(main())