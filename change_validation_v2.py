BGP Session State Validator

Captures BGP neighbor state snapshots before/after a network change and
compares them to detect session drops or unexpected prefix count changes.

Usage:
    # Capture pre-change baseline
    python bgp_state_monitor.py --host 10.0.0.1 --username admin --password secret \
        --device-type cisco_ios --snapshot pre-change.json

    # Validate post-change state against baseline
    python bgp_state_monitor.py --host 10.0.0.1 --username admin --password secret \
        --device-type cisco_ios --compare pre-change.json

Exit codes:
    0 — all sessions nominal (or snapshot saved successfully)
    1 — session drop, missing peer, or prefix count regression detected
    2 — usage error or connection failure

Prerequisites:
    pip install netmiko
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timezone

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(format="%(asctime)s [%(levelname)s] %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)

BGP_COMMANDS = {
    "cisco_ios": "show ip bgp summary",
    "cisco_xe": "show ip bgp summary",
    "cisco_nxos": "show bgp ipv4 unicast summary",
    "arista_eos": "show bgp summary",
    "juniper_junos": "show bgp summary",
}

# Matches neighbor lines: peer-IP  ... uptime  state-or-prefixcount
_PEER_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(\S+)",
    re.MULTILINE,
)


def parse_bgp_output(output: str) -> dict:
    peers = {}
    for m in _PEER_RE.finditer(output):
        peer, state = m.group(1), m.group(2)
        try:
            peers[peer] = {"established": True, "prefixes": int(state)}
        except ValueError:
            peers[peer] = {"established": False, "state": state, "prefixes": 0}
    return peers


def collect(conn, device_type: str) -> dict:
    cmd = BGP_COMMANDS.get(device_type, "show ip bgp summary")
    log.info("Sending: %s", cmd)
    output = conn.send_command(cmd)
    peers = parse_bgp_output(output)
    if not peers:
        log.warning("No BGP neighbors parsed — check device type or BGP config")
    else:
        log.info("Parsed %d neighbor(s)", len(peers))
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": conn.host,
        "device_type": device_type,
        "peers": peers,
    }


def compare(pre: dict, post: dict) -> int:
    pre_peers, post_peers = pre["peers"], post["peers"]
    issues = 0

    for peer, ps in pre_peers.items():
        if peer not in post_peers:
            log.error("PEER MISSING post-change: %s", peer)
            issues += 1
            continue

        cs = post_peers[peer]
        if ps["established"] and not cs["established"]:
            log.error("SESSION DOWN: %s  was=Established  now=%s", peer, cs.get("state", "?"))
            issues += 1
        elif ps["established"] and cs["established"]:
            delta = cs["prefixes"] - ps["prefixes"]
            if delta < 0:
                log.warning(
                    "PREFIX DROP: %s  pre=%d  post=%d  delta=%d",
                    peer, ps["prefixes"], cs["prefixes"], delta,
                )
                issues += 1
            else:
                log.info(
                    "OK: %s  pre=%d  post=%d  delta=+%d",
                    peer, ps["prefixes"], cs["prefixes"], delta,
                )
        else:
            log.info("STILL DOWN (pre+post): %s  state=%s", peer, cs.get("state", "?"))

    for peer in post_peers:
        if peer not in pre_peers:
            log.info("NEW PEER (not in baseline): %s", peer)

    if issues:
        log.error("%d issue(s) found — change validation FAILED", issues)
    else:
        log.info("All BGP sessions nominal — change validation PASSED")

    return 1 if issues else 0


def build_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="BGP session state validator (pre/post change)")
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(BGP_COMMANDS.keys()),
        metavar="TYPE",
        help="Netmiko device type (default: cisco_ios). Choices: " + ", ".join(BGP_COMMANDS),
    )
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--snapshot", metavar="FILE", help="Capture current state to FILE (pre-change)")
    p.add_argument("--compare", metavar="FILE", help="Compare current state against FILE (post-change)")
    return p.parse_args()


if __name__ == "__main__":
    args = build_args()

    if not args.snapshot and not args.compare:
        log.error("Provide --snapshot FILE to capture baseline or --compare FILE to validate.")
        sys.exit(2)

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }

    try:
        log.info("Connecting to %s as %s", args.host, args.username)
        with ConnectHandler(**device) as conn:
            snapshot = collect(conn, args.device_type)
    except NetmikoAuthenticationException:
        log.error("Authentication failed: %s", args.host)
        sys.exit(2)
    except NetmikoTimeoutException:
        log.error("Connection timed out: %s", args.host)
        sys.exit(2)

    if args.snapshot:
        with open(args.snapshot, "w") as fh:
            json.dump(snapshot, fh, indent=2)
        log.info("Baseline saved to %s  (%d peer(s))", args.snapshot, len(snapshot["peers"]))
        sys.exit(0)

    with open(args.compare) as fh:
        baseline = json.load(fh)

    log.info("Baseline timestamp: %s", baseline.get("timestamp", "unknown"))
    sys.exit(compare(baseline, snapshot))