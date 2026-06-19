```python
"""
bgp_state_checker.py - BGP Neighbor State Validator

Purpose:
    Connects to a router and validates BGP neighbor states. Designed as a
    pre/post change validation tool to confirm all BGP sessions remain
    established after network maintenance windows.

Usage:
    # Show all current BGP neighbor states
    python bgp_state_checker.py --host 192.168.1.1 --username admin --password secret

    # Save pre-change baseline
    python bgp_state_checker.py --host 192.168.1.1 --username admin \
        --password secret --save-baseline /tmp/bgp_pre.json

    # Validate post-change state against baseline
    python bgp_state_checker.py --host 192.168.1.1 --username admin \
        --password secret --compare-baseline /tmp/bgp_pre.json

    # Assert specific neighbors are Established (exits non-zero on failure)
    python bgp_state_checker.py --host 192.168.1.1 --username admin \
        --password secret --expected-neighbors peers.txt

Prerequisites:
    pip install netmiko
    Supported: cisco_ios, cisco_ios_xe, cisco_xr, juniper_junos
"""

import argparse
import json
import logging
import re
import sys
from pathlib import Path

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(format="%(asctime)s [%(levelname)s] %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)

SHOW_BGP_COMMANDS = {
    "cisco_ios": "show ip bgp summary",
    "cisco_ios_xe": "show ip bgp summary",
    "cisco_xr": "show bgp summary",
    "juniper_junos": "show bgp summary",
}

IOS_NEIGHBOR_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\S+\s+(\S+)",
    re.MULTILINE,
)


def parse_bgp_neighbors(output: str, device_type: str) -> dict:
    neighbors = {}
    if device_type in ("cisco_ios", "cisco_ios_xe", "cisco_xr"):
        for match in IOS_NEIGHBOR_RE.finditer(output):
            neighbors[match.group(1)] = match.group(2)
    elif device_type == "juniper_junos":
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2 and re.match(r"\d{1,3}(?:\.\d{1,3}){3}", parts[0]):
                neighbors[parts[0]] = parts[-1]
    return neighbors


def is_established(state: str) -> bool:
    return state.lower() in ("established", "estab")


def check_required(neighbors: dict, required: list) -> list:
    failures = []
    for ip in required:
        state = neighbors.get(ip)
        if state is None:
            failures.append(f"{ip}: not present in BGP table")
        elif not is_established(state):
            failures.append(f"{ip}: state={state} (expected Established)")
    return failures


def diff_baseline(current: dict, baseline: dict) -> list:
    diffs = []
    for ip, old_state in baseline.items():
        new_state = current.get(ip)
        if new_state is None:
            diffs.append(f"{ip}: disappeared (was {old_state})")
        elif new_state.lower() != old_state.lower():
            diffs.append(f"{ip}: {old_state} -> {new_state}")
    for ip in current:
        if ip not in baseline:
            diffs.append(f"{ip}: new neighbor added (state={current[ip]})")
    return diffs


def fetch_bgp_neighbors(args) -> dict:
    device_params = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "conn_timeout": 30,
    }
    command = SHOW_BGP_COMMANDS[args.device_type]
    log.info("Connecting to %s as %s", args.host, args.username)
    try:
        with ConnectHandler(**device_params) as conn:
            log.info("Fetching: %s", command)
            output = conn.send_command(command, read_timeout=60)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        sys.exit(1)

    neighbors = parse_bgp_neighbors(output, args.device_type)
    log.info("Parsed %d BGP neighbors", len(neighbors))
    return neighbors


def main():
    parser = argparse.ArgumentParser(description="Validate BGP neighbor states")
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(SHOW_BGP_COMMANDS.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument(
        "--expected-neighbors",
        metavar="FILE",
        help="File with one neighbor IP per line; exits 1 if any not Established",
    )
    parser.add_argument(
        "--save-baseline",
        metavar="FILE",
        help="Write current BGP state to JSON for later comparison",
    )
    parser.add_argument(
        "--compare-baseline",
        metavar="FILE",
        help="Diff current state against a saved baseline JSON",
    )
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    neighbors = fetch_bgp_neighbors(args)
    for ip, state in sorted(neighbors.items()):
        log.info("  %-20s  %s", ip, state)

    exit_code = 0

    if args.save_baseline:
        Path(args.save_baseline).write_text(json.dumps(neighbors, indent=2))
        log.info("Baseline saved to %s", args.save_baseline)

    if args.compare_baseline:
        baseline = json.loads(Path(args.compare_baseline).read_text())
        diffs = diff_baseline(neighbors, baseline)
        if not diffs:
            log.info("PASS: BGP state matches baseline (%d neighbors)", len(neighbors))
        else:
            log.error("FAIL: %d difference(s) from baseline:", len(diffs))
            for d in diffs:
                log.error("  %s", d)
            exit_code = 1

    if args.expected_neighbors:
        required = [
            line.strip()
            for line in Path(args.expected_neighbors).read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        failures = check_required(neighbors, required)
        if not failures:
            log.info("PASS: All %d required neighbors are Established", len(required))
        else:
            log.error("FAIL: %d neighbor(s) not Established:", len(failures))
            for f in failures:
                log.error("  %s", f)
            exit_code = 1

    if not any([args.expected_neighbors, args.compare_baseline, args.save_baseline]):
        not_up = {ip: st for ip, st in neighbors.items() if not is_established(st)}
        if not_up:
            log.warning("%d neighbor(s) not in Established state:", len(not_up))
            for ip, st in sorted(not_up.items()):
                log.warning("  %-20s  %s", ip, st)
            exit_code = 1
        else:
            log.info("PASS: All %d neighbors Established", len(neighbors))

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
```