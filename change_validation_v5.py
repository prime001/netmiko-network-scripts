bgp_session_audit.py - BGP neighbor session auditor for change validation.

Purpose:
    Captures BGP neighbor states from a device and optionally compares against
    a saved baseline to detect session changes introduced during maintenance.
    Use before/after change windows to confirm BGP stability.

Usage:
    # Save baseline before a change:
    python bgp_session_audit.py --host 192.168.1.1 --username admin --password secret \
        --device-type cisco_ios --save-baseline /tmp/bgp_pre.json

    # Validate after the change (diff against baseline):
    python bgp_session_audit.py --host 192.168.1.1 --username admin --password secret \
        --device-type cisco_ios --compare-baseline /tmp/bgp_pre.json

    # Standalone health check (all neighbors must be Established):
    python bgp_session_audit.py --host 192.168.1.1 --username admin --password secret \
        --device-type cisco_ios

Prerequisites:
    pip install netmiko
    Device must have BGP configured.
    Supported platforms: cisco_ios, cisco_ios_xe, cisco_nxos, juniper_junos.
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

BGP_COMMANDS = {
    "cisco_ios": "show bgp summary",
    "cisco_ios_xe": "show bgp summary",
    "cisco_nxos": "show bgp summary",
    "juniper_junos": "show bgp summary",
}

_CISCO_PATTERN = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3}|\S+:\S+)\s+\d+\s+\d+\s+\d+"
    r"\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\w+)",
    re.MULTILINE,
)
_JUNIPER_PATTERN = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3}|\S+:\S+)\s+\d+\s+\S+\s+\S+\s+\S+\s+(\w+)",
    re.MULTILINE,
)


def _platform_family(device_type: str) -> str:
    return "juniper" if device_type.startswith("juniper") else "cisco"


def parse_bgp_neighbors(output: str, device_type: str) -> dict:
    """Return {neighbor_ip: state} from show bgp summary output."""
    pattern = _JUNIPER_PATTERN if _platform_family(device_type) == "juniper" else _CISCO_PATTERN
    return {m.group(1): m.group(2) for m in pattern.finditer(output)}


def collect(args) -> dict:
    """Connect to device, run BGP summary, return structured result."""
    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "timeout": args.timeout,
    }
    if args.secret:
        device["secret"] = args.secret

    log.info("Connecting to %s (%s)", args.host, args.device_type)
    try:
        with ConnectHandler(**device) as conn:
            if args.secret:
                conn.enable()
            cmd = BGP_COMMANDS.get(args.device_type, "show bgp summary")
            log.info("Sending: %s", cmd)
            output = conn.send_command(cmd, read_timeout=30)
    except AuthenticationException:
        log.error("Authentication failed for %s", args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", args.host)
        sys.exit(1)

    return {
        "host": args.host,
        "device_type": args.device_type,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "neighbors": parse_bgp_neighbors(output, args.device_type),
        "raw_output": output,
    }


def check_established(neighbors: dict) -> tuple:
    """Return (all_up: bool, problems: list of (ip, state))."""
    problems = [(ip, st) for ip, st in neighbors.items() if st.lower() != "established"]
    return (len(problems) == 0, problems)


def diff_baselines(baseline: dict, current: dict) -> tuple:
    """Return (clean: bool, diff: dict) comparing neighbor states."""
    base = baseline["neighbors"]
    curr = current["neighbors"]
    added = {ip: st for ip, st in curr.items() if ip not in base}
    removed = {ip: st for ip, st in base.items() if ip not in curr}
    changed = {
        ip: {"before": base[ip], "after": curr[ip]}
        for ip in base
        if ip in curr and base[ip] != curr[ip]
    }
    return not (added or removed or changed), {"added": added, "removed": removed, "changed": changed}


def print_table(neighbors: dict) -> None:
    if not neighbors:
        print("  (no neighbors parsed from output)")
        return
    print(f"  {'Neighbor':<40} {'State'}")
    print("  " + "-" * 55)
    for ip in sorted(neighbors):
        state = neighbors[ip]
        flag = "" if state.lower() == "established" else "  <-- NOT ESTABLISHED"
        print(f"  {ip:<40} {state}{flag}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Audit BGP neighbor session states; diff against a pre-change baseline."
    )
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(BGP_COMMANDS.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--timeout", type=int, default=60, help="SSH timeout in seconds")
    p.add_argument("--secret", default="", help="Enable/privilege secret")
    p.add_argument("--save-baseline", metavar="FILE", help="Save current BGP state as JSON baseline")
    p.add_argument("--compare-baseline", metavar="FILE", help="Diff current state against saved baseline")
    return p


def main() -> int:
    args = build_parser().parse_args()
    result = collect(args)
    neighbors = result["neighbors"]

    print(f"\n=== BGP Session Audit: {args.host} ===")
    print(f"Timestamp : {result['timestamp']}")
    print(f"Neighbors : {len(neighbors)}\n")
    print_table(neighbors)

    if args.save_baseline:
        path = Path(args.save_baseline)
        path.write_text(json.dumps(result, indent=2))
        log.info("Baseline saved to %s", path)

    exit_code = 0

    if args.compare_baseline:
        bpath = Path(args.compare_baseline)
        if not bpath.exists():
            log.error("Baseline file not found: %s", bpath)
            return 1
        baseline = json.loads(bpath.read_text())
        clean, diff = diff_baselines(baseline, result)
        print(f"\n=== Baseline Comparison  (pre-change: {baseline['timestamp']}) ===")
        if clean:
            print("  PASS: No BGP session changes detected.\n")
        else:
            exit_code = 1
            print("  FAIL: BGP session changes detected:")
            for ip, st in diff["added"].items():
                print(f"    + ADDED    {ip}  ({st})")
            for ip, st in diff["removed"].items():
                print(f"    - REMOVED  {ip}  ({st})")
            for ip, ch in diff["changed"].items():
                print(f"    ~ CHANGED  {ip}  {ch['before']} -> {ch['after']}")
            print()
    else:
        all_up, problems = check_established(neighbors)
        print(f"\n=== Health Check ===")
        if all_up:
            print(f"  PASS: All {len(neighbors)} BGP neighbor(s) are Established.\n")
        else:
            exit_code = 1
            print(f"  FAIL: {len(problems)} of {len(neighbors)} neighbor(s) not Established:")
            for ip, st in problems:
                print(f"    {ip}: {st}")
            print()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())