bgp_state_validator.py - BGP neighbor state validator for pre/post change verification.

Purpose:
    Captures BGP neighbor state and received prefix counts, saves a baseline snapshot
    before a maintenance window, then compares post-change state to detect session
    loss or significant prefix-count degradation introduced by the change.

Usage:
    # Save a pre-change baseline
    python bgp_state_validator.py --host 10.0.0.1 -u admin -p secret --save-baseline /tmp/bgp_pre.json

    # Validate post-change state against the baseline
    python bgp_state_validator.py --host 10.0.0.1 -u admin -p secret --compare /tmp/bgp_pre.json

    # Print current BGP summary without saving or comparing
    python bgp_state_validator.py --host 10.0.0.1 -u admin -p secret

Prerequisites:
    pip install netmiko
    SSH access to the device with privilege level sufficient to run 'show ip bgp summary'.
    Supported platforms: Cisco IOS, IOS-XE, NX-OS, Arista EOS.
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

DEVICE_TYPE_MAP = {
    "ios": "cisco_ios",
    "iosxe": "cisco_xe",
    "nxos": "cisco_nxos",
    "eos": "arista_eos",
}

PREFIX_DROP_THRESHOLD = 20.0


def _parse_bgp_summary_tabular(output: str) -> dict:
    """Parse IOS/IOS-XE/EOS/NX-OS 'show [ip] bgp summary' neighbor table rows."""
    neighbors = {}
    pattern = re.compile(
        r"^(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(\S+)",
        re.MULTILINE,
    )
    for match in pattern.finditer(output):
        ip, remote_as, state_field = match.groups()
        try:
            prefixes = int(state_field)
            state = "Established"
        except ValueError:
            prefixes = 0
            state = state_field
        neighbors[ip] = {"remote_as": remote_as, "state": state, "prefixes_received": prefixes}
    return neighbors


def fetch_bgp_neighbors(conn, netmiko_type: str) -> dict:
    """Run the appropriate show command and return parsed neighbor dict."""
    if netmiko_type in ("cisco_ios", "cisco_xe"):
        raw = conn.send_command("show ip bgp summary")
    else:
        raw = conn.send_command("show bgp summary")
    return _parse_bgp_summary_tabular(raw)


def build_snapshot(host: str, neighbors: dict) -> dict:
    return {
        "host": host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "neighbors": neighbors,
    }


def compare_snapshots(baseline: dict, current: dict) -> tuple:
    """Return (passed: bool, issues: list[str]) comparing current to baseline."""
    issues = []
    passed = True
    base_neighbors = baseline.get("neighbors", {})
    curr_neighbors = current.get("neighbors", {})

    for ip, base in base_neighbors.items():
        if base["state"] != "Established":
            continue
        if ip not in curr_neighbors:
            issues.append(f"MISSING  {ip} AS{base['remote_as']} — no longer in BGP table")
            passed = False
            continue
        curr = curr_neighbors[ip]
        if curr["state"] != "Established":
            issues.append(
                f"DOWN     {ip} AS{base['remote_as']} — state: Established -> {curr['state']}"
            )
            passed = False
        elif base["prefixes_received"] > 0:
            drop_pct = (base["prefixes_received"] - curr["prefixes_received"]) / base["prefixes_received"] * 100
            if drop_pct > PREFIX_DROP_THRESHOLD:
                issues.append(
                    f"PREFIXES {ip} AS{base['remote_as']} — "
                    f"{base['prefixes_received']} -> {curr['prefixes_received']} "
                    f"({drop_pct:.1f}% drop)"
                )
                passed = False

    for ip in set(curr_neighbors) - set(base_neighbors):
        issues.append(f"NEW      {ip} AS{curr_neighbors[ip]['remote_as']} — appeared since baseline")

    return passed, issues


def print_summary_table(neighbors: dict) -> None:
    print(f"\n{'Neighbor':<18} {'Remote AS':<12} {'State':<14} {'Pfx Rcvd':>8}")
    print("-" * 56)
    for ip in sorted(neighbors):
        d = neighbors[ip]
        print(f"{ip:<18} {d['remote_as']:<12} {d['state']:<14} {d['prefixes_received']:>8}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BGP neighbor state validator for pre/post change windows"
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument(
        "--device-type", default="ios", choices=list(DEVICE_TYPE_MAP),
        help="Device OS (default: ios)"
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--save-baseline", metavar="FILE", help="Save snapshot to FILE (pre-change)")
    parser.add_argument("--compare", metavar="FILE", help="Compare current state against FILE")
    parser.add_argument("--verbose", action="store_true", help="Always print neighbor table")
    args = parser.parse_args()

    netmiko_type = DEVICE_TYPE_MAP[args.device_type]
    device_params = {
        "device_type": netmiko_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }

    logger.info("Connecting to %s as %s", args.host, args.username)
    try:
        with ConnectHandler(**device_params) as conn:
            logger.info("Fetching BGP summary")
            neighbors = fetch_bgp_neighbors(conn, netmiko_type)
    except NetmikoAuthenticationException:
        logger.error("Authentication failed — check username/password")
        sys.exit(1)
    except NetmikoTimeoutException:
        logger.error("Connection timed out to %s:%d", args.host, args.port)
        sys.exit(1)

    established = sum(1 for n in neighbors.values() if n["state"] == "Established")
    logger.info("BGP peers: %d established / %d total", established, len(neighbors))

    if args.verbose or not (args.save_baseline or args.compare):
        print_summary_table(neighbors)

    snapshot = build_snapshot(args.host, neighbors)

    if args.save_baseline:
        Path(args.save_baseline).write_text(json.dumps(snapshot, indent=2))
        logger.info("Baseline saved to %s", args.save_baseline)

    if args.compare:
        baseline_path = Path(args.compare)
        if not baseline_path.exists():
            logger.error("Baseline file not found: %s", args.compare)
            sys.exit(1)
        baseline = json.loads(baseline_path.read_text())
        logger.info(
            "Comparing against baseline captured %s from %s",
            baseline.get("timestamp", "unknown"),
            baseline.get("host", "unknown"),
        )
        passed, issues = compare_snapshots(baseline, snapshot)
        for issue in issues:
            if issue.startswith("NEW"):
                logger.info(issue)
            else:
                logger.error(issue)
        if passed:
            logger.info("RESULT: PASS — BGP state matches baseline")
        else:
            logger.error("RESULT: FAIL — BGP degradation detected post-change")
            sys.exit(2)


if __name__ == "__main__":
    main()