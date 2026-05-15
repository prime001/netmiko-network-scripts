The repo context is clear. Writing the BGP neighbor health check script now — this is a focused operational tool distinct from the generic health_check.py/v2 scripts.

"""
bgp_neighbor_check.py — BGP session state and prefix-count auditor.

Connects to a Cisco IOS/IOS-XE router via Netmiko and inspects all BGP
neighbors reported by 'show ip bgp summary'.  Each neighbor is evaluated
against two pass/fail criteria:

  1. Session state must be "Established".
  2. Received prefix count must meet or exceed --min-prefixes (default 0).

Exit codes:
  0  all neighbors healthy
  1  one or more neighbors failed the check
  2  connection / authentication error

Usage:
  python bgp_neighbor_check.py --host 10.0.0.1 --username admin
  python bgp_neighbor_check.py --host 10.0.0.1 --username admin \
      --device-type cisco_ios --min-prefixes 100 --timeout 30

Prerequisites:
  pip install netmiko
"""

import argparse
import getpass
import logging
import re
import sys
from dataclasses import dataclass
from typing import List

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

# Matches an IPv4 address at the start of a BGP summary table row.
_PEER_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s")


@dataclass
class BgpNeighbor:
    peer: str
    remote_as: str
    msg_rcvd: int
    msg_sent: int
    uptime: str
    state_or_pfxrcd: str

    @property
    def established(self) -> bool:
        return self.state_or_pfxrcd.lstrip("-").isdigit()

    @property
    def prefix_count(self) -> int:
        return int(self.state_or_pfxrcd) if self.established else 0

    @property
    def state(self) -> str:
        return "Established" if self.established else self.state_or_pfxrcd


def parse_bgp_summary(output: str) -> List[BgpNeighbor]:
    neighbors: List[BgpNeighbor] = []
    in_table = False

    for line in output.splitlines():
        if "Neighbor" in line and "MsgRcvd" in line:
            in_table = True
            continue
        if not in_table or not line.strip():
            continue
        if not _PEER_RE.match(line):
            continue

        parts = line.split()
        # IOS BGP summary row: Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd
        if len(parts) < 10:
            continue

        neighbors.append(
            BgpNeighbor(
                peer=parts[0],
                remote_as=parts[2],
                msg_rcvd=_to_int(parts[3]),
                msg_sent=_to_int(parts[4]),
                uptime=parts[8],
                state_or_pfxrcd=parts[9],
            )
        )

    return neighbors


def _to_int(value: str) -> int:
    try:
        return int(value)
    except ValueError:
        return 0


def audit_neighbors(neighbors: List[BgpNeighbor], min_prefixes: int) -> List[str]:
    failures: List[str] = []

    for n in neighbors:
        if not n.established:
            failures.append(
                f"FAIL  peer={n.peer} AS={n.remote_as} state={n.state} uptime={n.uptime}"
            )
        elif n.prefix_count < min_prefixes:
            failures.append(
                f"FAIL  peer={n.peer} AS={n.remote_as} state={n.state} "
                f"prefixes={n.prefix_count} < threshold={min_prefixes}"
            )
        else:
            log.info(
                "OK    peer=%s AS=%s state=%s prefixes=%d uptime=%s",
                n.peer, n.remote_as, n.state, n.prefix_count, n.uptime,
            )

    return failures


def run(args: argparse.Namespace) -> int:
    conn_params = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "timeout": args.timeout,
    }

    try:
        log.info("Connecting to %s", args.host)
        with ConnectHandler(**conn_params) as conn:
            output = conn.send_command("show ip bgp summary")
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 2
    except NetmikoTimeoutException:
        log.error("Connection timed out: %s", args.host)
        return 2
    except Exception as exc:
        log.error("Connection error: %s", exc)
        return 2

    neighbors = parse_bgp_summary(output)
    if not neighbors:
        log.warning("No BGP neighbors found — verify BGP is configured and device-type is correct")
        return 1

    log.info("Evaluating %d BGP neighbor(s) on %s", len(neighbors), args.host)
    failures = audit_neighbors(neighbors, args.min_prefixes)

    if failures:
        for msg in failures:
            print(msg)
        print(f"\n{len(failures)}/{len(neighbors)} neighbor(s) failed on {args.host}")
        return 1

    print(f"All {len(neighbors)} BGP neighbor(s) healthy on {args.host}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Audit BGP neighbor states and prefix counts via Netmiko"
    )
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("--username", required=True)
    p.add_argument(
        "--password",
        default=None,
        help="SSH password — omit to prompt interactively",
    )
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        dest="device_type",
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--timeout", type=int, default=30, help="SSH connect timeout in seconds")
    p.add_argument(
        "--min-prefixes",
        type=int,
        default=0,
        dest="min_prefixes",
        help="Minimum accepted received-prefix count per neighbor (default: 0)",
    )
    p.add_argument("--debug", action="store_true")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.password is None:
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    sys.exit(run(args))