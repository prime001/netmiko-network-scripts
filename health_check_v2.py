bgp_state_check.py — BGP neighbor state monitor for Cisco IOS/IOS-XE/IOS-XR and Juniper JunOS.

Connects to a router, pulls BGP summary output, and reports each neighbor's
state and prefix count. Alerts on down neighbors and optional prefix thresholds.

Usage:
    python bgp_state_check.py -d 10.0.0.1 -u admin -p secret
    python bgp_state_check.py -d 10.0.0.1 -u admin -p secret --device-type juniper_junos
    python bgp_state_check.py -d 10.0.0.1 -u admin -p secret --min-prefixes 100 --max-prefixes 800000

Prerequisites:
    pip install netmiko

Exit codes:
    0  All BGP neighbors established and within prefix thresholds
    1  One or more neighbors down or threshold violated
    2  Connection or authentication failure
"""

import argparse
import logging
import re
import sys

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.WARNING)
logger = logging.getLogger(__name__)

SUPPORTED_DEVICE_TYPES = ["cisco_ios", "cisco_xe", "cisco_xr", "juniper_junos"]


def parse_ios_bgp_summary(output):
    neighbors = []
    in_data = False
    for line in output.splitlines():
        if re.match(r"^\s*Neighbor\s+V\s+AS", line):
            in_data = True
            continue
        if not in_data:
            continue
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 9:
            continue
        neighbors.append({
            "neighbor": parts[0],
            "as": parts[2],
            "updown": parts[7],
            "state_or_prefixes": parts[8],
        })
    return neighbors


def parse_junos_bgp_summary(output):
    neighbors = []
    for line in output.splitlines():
        m = re.match(
            r"^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+\d+\s+(\S+)\s+(\S+)\s+\S+\s+(\S+)", line.strip()
        )
        if m:
            neighbors.append({
                "neighbor": m.group(1),
                "as": m.group(2),
                "updown": m.group(3),
                "state_or_prefixes": m.group(5),
            })
    return neighbors


def evaluate_neighbor(neighbor, min_prefixes, max_prefixes):
    state = neighbor["state_or_prefixes"]
    nbr = neighbor["neighbor"]
    asn = neighbor["as"]
    updown = neighbor["updown"]

    if state.isdigit():
        count = int(state)
        if min_prefixes and count < min_prefixes:
            return False, (
                f"WARN  {nbr} (AS {asn}) established but only {count} prefixes "
                f"(min: {min_prefixes}), up {updown}"
            )
        if max_prefixes and count > max_prefixes:
            return False, (
                f"WARN  {nbr} (AS {asn}) prefix count {count} exceeds "
                f"max {max_prefixes}, up {updown}"
            )
        return True, f"OK    {nbr} (AS {asn}) established, {count} prefixes, up {updown}"

    return False, f"DOWN  {nbr} (AS {asn}) state={state}, up/down: {updown}"


def run_check(args):
    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "timeout": args.timeout,
        "conn_timeout": args.timeout,
    }
    if args.enable_secret:
        device_params["secret"] = args.enable_secret

    try:
        logger.info("Connecting to %s", args.device)
        with ConnectHandler(**device_params) as conn:
            if args.enable_secret:
                conn.enable()
            if args.device_type in ("cisco_ios", "cisco_xe"):
                raw = conn.send_command("show ip bgp summary")
                neighbors = parse_ios_bgp_summary(raw)
            elif args.device_type == "cisco_xr":
                raw = conn.send_command("show bgp ipv4 unicast summary")
                neighbors = parse_ios_bgp_summary(raw)
            else:
                raw = conn.send_command("show bgp summary")
                neighbors = parse_junos_bgp_summary(raw)
    except AuthenticationException:
        print(f"Authentication failed for {args.device}", file=sys.stderr)
        return 2
    except NetmikoTimeoutException:
        print(f"Connection timed out to {args.device}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Connection error: {exc}", file=sys.stderr)
        return 2

    if not neighbors:
        print(f"No BGP neighbors parsed from {args.device} — verify device-type and BGP config.")
        return 1

    failures = 0
    print(f"\nBGP Neighbor Status — {args.device} ({args.device_type})")
    print("-" * 65)
    for nbr in neighbors:
        ok, msg = evaluate_neighbor(nbr, args.min_prefixes, args.max_prefixes)
        print(msg)
        if not ok:
            failures += 1
    print("-" * 65)
    total = len(neighbors)
    print(f"Result: {total - failures}/{total} neighbors healthy\n")
    return 0 if failures == 0 else 1


def build_parser():
    parser = argparse.ArgumentParser(
        description="Check BGP neighbor states and prefix counts via netmiko."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="Login username")
    parser.add_argument("-p", "--password", required=True, help="Login password")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=SUPPORTED_DEVICE_TYPES,
        dest="device_type",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--timeout", type=int, default=30, help="Connection timeout in seconds (default: 30)"
    )
    parser.add_argument(
        "--enable-secret", dest="enable_secret", default="",
        help="Enable/privileged mode secret"
    )
    parser.add_argument(
        "--min-prefixes", type=int, default=0, dest="min_prefixes",
        help="Alert when an established neighbor advertises fewer than N prefixes"
    )
    parser.add_argument(
        "--max-prefixes", type=int, default=0, dest="max_prefixes",
        help="Alert when an established neighbor exceeds N prefixes"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    sys.exit(run_check(args))