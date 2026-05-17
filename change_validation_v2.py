The script content (as requested, no fences):

```
"""
BGP Neighbor Validator

Connects to a router and validates BGP session states against an expected
peer list. Use this after BGP configuration changes, maintenance windows,
or router failovers to confirm all sessions are Established.

Usage:
    python bgp_neighbor_validator.py -d 192.168.1.1 -u admin -p secret
    python bgp_neighbor_validator.py -d 192.168.1.1 -u admin -p secret --peers-file peers.json
    python bgp_neighbor_validator.py -d 192.168.1.1 -u admin -p secret --expect 10.0.0.1 10.0.0.2
    python bgp_neighbor_validator.py -d 192.168.1.1 -u admin -p secret --show-all

Prerequisites:
    pip install netmiko

peers.json format:
    [
        {"neighbor": "10.0.0.1", "remote_as": "65001", "description": "upstream-A"},
        {"neighbor": "10.0.0.2", "remote_as": "65002"}
    ]

Exit codes:
    0 — all expected peers are Established
    1 — connection or parse error
    2 — one or more expected peers are down or missing
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


@dataclass
class BgpNeighbor:
    neighbor: str
    remote_as: str
    state: str
    prefixes_received: Optional[int]
    uptime: str

    @property
    def is_established(self) -> bool:
        # IOS encodes Established state as a numeric prefix count
        return self.state.lower() == "established" or self.state.isdigit()


def parse_bgp_summary(output: str) -> list:
    """Parse 'show ip bgp summary' from Cisco IOS/IOS-XE.

    Neighbor lines follow: <IP> <ver> <AS> <rcvd> <sent> <tbl> <inq> <outq> <uptime> <state/pfx>
    """
    neighbors = []
    pattern = re.compile(
        r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)",
        re.MULTILINE,
    )
    for m in pattern.finditer(output):
        ip, remote_as, uptime, state_or_pfx = m.groups()
        neighbors.append(
            BgpNeighbor(
                neighbor=ip,
                remote_as=remote_as,
                state="Established" if state_or_pfx.isdigit() else state_or_pfx,
                prefixes_received=int(state_or_pfx) if state_or_pfx.isdigit() else None,
                uptime=uptime,
            )
        )
    return neighbors


def load_peers_file(path: str) -> list:
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Failed to load peers file %s: %s", path, exc)
        sys.exit(1)


def validate(actual: list, expected_ips: list) -> tuple:
    """Return (passed, failed_down, missing) neighbor IP lists."""
    actual_map = {n.neighbor: n for n in actual}
    passed, failed_down, missing = [], [], []
    for ip in expected_ips:
        if ip not in actual_map:
            missing.append(ip)
        elif actual_map[ip].is_established:
            passed.append(ip)
        else:
            failed_down.append(ip)
    return passed, failed_down, missing


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Validate BGP neighbor session states on a Cisco IOS/IOS-XE router."
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--peers-file", help="JSON file listing expected BGP peer IPs")
    p.add_argument(
        "--expect",
        nargs="+",
        metavar="IP",
        help="One or more expected BGP neighbor IPs",
    )
    p.add_argument(
        "--show-all",
        action="store_true",
        help="Print all discovered neighbors regardless of expected list",
    )
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


def main() -> int:
    args = build_parser().parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    expected_ips = []
    if args.peers_file:
        peers_data = load_peers_file(args.peers_file)
        expected_ips.extend(p["neighbor"] for p in peers_data)
    if args.expect:
        expected_ips.extend(args.expect)
    seen = set()
    expected_ips = [x for x in expected_ips if not (x in seen or seen.add(x))]

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }

    logger.info("Connecting to %s (%s)...", args.device, args.device_type)
    try:
        with ConnectHandler(**device_params) as conn:
            hostname = conn.find_prompt().rstrip("#>")
            logger.info("Connected to %s", hostname)
            output = conn.send_command("show ip bgp summary")
    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s", args.device)
        return 1
    except NetmikoTimeoutException:
        logger.error("Connection timed out to %s", args.device)
        return 1
    except Exception as exc:
        logger.error("Unexpected connection error: %s", exc)
        return 1

    neighbors = parse_bgp_summary(output)
    if not neighbors:
        logger.warning(
            "No BGP neighbors parsed. Verify device type or run with --debug to see raw output."
        )
        if args.debug:
            print(output)
        return 1

    if args.show_all:
        print(f"\n{'Neighbor':<18} {'AS':<8} {'State':<14} {'Uptime':<12} {'Prefixes':>8}")
        print("-" * 64)
        for n in sorted(neighbors, key=lambda x: x.neighbor):
            pfx = str(n.prefixes_received) if n.prefixes_received is not None else "-"
            print(f"{n.neighbor:<18} {n.remote_as:<8} {n.state:<14} {n.uptime:<12} {pfx:>8}")

    if not expected_ips:
        logger.info(
            "No expected peers specified — found %d neighbor(s). "
            "Use --expect or --peers-file to validate.",
            len(neighbors),
        )
        return 0

    passed, failed_down, missing = validate(neighbors, expected_ips)
    actual_map = {n.neighbor: n for n in neighbors}

    print(f"\nBGP Validation Results — {hostname} ({args.device})")
    print("=" * 56)
    for ip in passed:
        n = actual_map[ip]
        pfx = f"  [{n.prefixes_received} pfx]" if n.prefixes_received is not None else ""
        print(f"  PASS  {ip:<18} Established  up {n.uptime}{pfx}")
    for ip in failed_down:
        n = actual_map[ip]
        print(f"  FAIL  {ip:<18} {n.state}")
    for ip in missing:
        print(f"  MISS  {ip:<18} not present in BGP table")

    total = len(expected_ips)
    print(
        f"\nSummary: {len(passed)}/{total} passed, "
        f"{len(failed_down)} down, {len(missing)} missing"
    )

    return 0 if not failed_down and not missing else 2


if __name__ == "__main__":
    sys.exit(main())
```

**What this does:** BGP neighbor validator — connects via netmiko, runs `show ip bgp summary`, parses all neighbors and their session states, then validates them against an expected peer list (from `--expect` IPs or a `--peers-file` JSON). Returns exit code 0/1/2 for CI/pipeline integration. Distinct from all existing scripts in the repo and covers a real post-change validation workflow network engineers actually run.