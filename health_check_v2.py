BGP Neighbor Health Check

Connects to a router via netmiko, collects BGP neighbor state and prefix
statistics, and reports peers that are down or have crossed prefix thresholds.

Prerequisites:
    pip install netmiko

Usage:
    python bgp_neighbor_check.py -d 192.168.1.1 -u admin -p secret
    python bgp_neighbor_check.py -d 10.0.0.1 -u admin -p secret \
        --device-type cisco_nxos --max-prefixes 500000 --warn-below 10
    python bgp_neighbor_check.py -d 10.0.0.1 -u admin -p secret --json

Supported device types: cisco_ios, cisco_xe, cisco_nxos
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from typing import List, Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


@dataclass
class BgpPeer:
    neighbor: str
    asn: str
    state: str
    prefixes_received: int = 0
    uptime: str = "never"
    is_up: bool = False


@dataclass
class CheckResult:
    host: str
    peers: List[BgpPeer] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def down_peers(self) -> List[BgpPeer]:
        return [p for p in self.peers if not p.is_up]

    @property
    def ok(self) -> bool:
        return not self.down_peers and not self.errors


def parse_ios_summary(output: str) -> List[BgpPeer]:
    peers = []
    pattern = re.compile(
        r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\d+\s+(\d+)"
        r"\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)",
        re.MULTILINE,
    )
    for m in pattern.finditer(output):
        neighbor, asn, updown, state_or_pfx = m.groups()
        try:
            prefixes = int(state_or_pfx)
            state = "Established"
            is_up = True
        except ValueError:
            prefixes = 0
            state = state_or_pfx
            is_up = False
        peers.append(BgpPeer(
            neighbor=neighbor,
            asn=asn,
            state=state,
            prefixes_received=prefixes,
            uptime=updown,
            is_up=is_up,
        ))
    return peers


def parse_nxos_summary(output: str) -> List[BgpPeer]:
    peers = []
    pattern = re.compile(
        r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d+)"
        r"\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)",
        re.MULTILINE,
    )
    for m in pattern.finditer(output):
        neighbor, asn, updown, state_or_pfx = m.groups()
        try:
            prefixes = int(state_or_pfx)
            state = "Established"
            is_up = True
        except ValueError:
            prefixes = 0
            state = state_or_pfx
            is_up = False
        peers.append(BgpPeer(
            neighbor=neighbor,
            asn=asn,
            state=state,
            prefixes_received=prefixes,
            uptime=updown,
            is_up=is_up,
        ))
    return peers


def run_check(
    host: str,
    username: str,
    password: str,
    device_type: str,
    max_prefixes: Optional[int],
    warn_below: int,
) -> CheckResult:
    result = CheckResult(host=host)
    conn_params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
    }
    try:
        log.info("Connecting to %s (%s)", host, device_type)
        with ConnectHandler(**conn_params) as conn:
            output = conn.send_command("show bgp summary", expect_string=r"#")
    except NetmikoAuthenticationException:
        result.errors.append("Authentication failed")
        return result
    except NetmikoTimeoutException:
        result.errors.append("Connection timed out")
        return result
    except Exception as exc:
        result.errors.append(f"Connection error: {exc}")
        return result

    if "nxos" in device_type:
        result.peers = parse_nxos_summary(output)
    else:
        result.peers = parse_ios_summary(output)

    if not result.peers and "BGP" not in output:
        result.errors.append("BGP not configured or no summary output found")
        return result

    for peer in result.peers:
        if peer.is_up and max_prefixes and peer.prefixes_received > max_prefixes:
            result.errors.append(
                f"{peer.neighbor} prefix count {peer.prefixes_received} "
                f"exceeds limit {max_prefixes}"
            )
        if peer.is_up and peer.prefixes_received < warn_below:
            result.errors.append(
                f"{peer.neighbor} only {peer.prefixes_received} prefixes "
                f"received (below threshold {warn_below})"
            )

    return result


def print_report(result: CheckResult, as_json: bool) -> None:
    if as_json:
        data = {
            "host": result.host,
            "ok": result.ok,
            "peers": [
                {
                    "neighbor": p.neighbor,
                    "asn": p.asn,
                    "state": p.state,
                    "prefixes_received": p.prefixes_received,
                    "uptime": p.uptime,
                    "is_up": p.is_up,
                }
                for p in result.peers
            ],
            "errors": result.errors,
        }
        print(json.dumps(data, indent=2))
        return

    status = "OK" if result.ok else "FAIL"
    print(f"\n[{status}] BGP summary for {result.host}")
    print(f"  Total peers: {len(result.peers)}  "
          f"Up: {sum(p.is_up for p in result.peers)}  "
          f"Down: {len(result.down_peers)}")
    print()

    for peer in result.peers:
        flag = "UP  " if peer.is_up else "DOWN"
        pfx = f"{peer.prefixes_received} pfx" if peer.is_up else peer.state
        print(f"  [{flag}] {peer.neighbor:<18} AS{peer.asn:<8} "
              f"uptime={peer.uptime:<12} {pfx}")

    if result.errors:
        print("\n  Warnings/Errors:")
        for err in result.errors:
            print(f"    ! {err}")
    print()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Check BGP neighbor health on a Cisco router or switch."
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=["cisco_ios", "cisco_xe", "cisco_nxos"],
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument(
        "--max-prefixes",
        type=int,
        default=None,
        help="Alert if any peer advertises more than this many prefixes",
    )
    p.add_argument(
        "--warn-below",
        type=int,
        default=1,
        help="Alert if an established peer sends fewer than this many prefixes (default: 1)",
    )
    p.add_argument("--json", action="store_true", help="Output results as JSON")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    result = run_check(
        host=args.device,
        username=args.username,
        password=args.password,
        device_type=args.device_type,
        max_prefixes=args.max_prefixes,
        warn_below=args.warn_below,
    )
    print_report(result, as_json=args.json)
    sys.exit(0 if result.ok else 1)