```python
"""
bgp_session_monitor.py - BGP Neighbor Health Checker

Connects to a Cisco IOS/XE/XR/NX-OS device via SSH and audits all BGP
neighbor sessions: state, uptime, and received prefix counts. Exits
non-zero when any session is not Established or a prefix count threshold
is breached. Useful for automated NOC checks or pre/post-change validation.

Usage:
    python bgp_session_monitor.py -d 192.168.1.1 -u admin
    python bgp_session_monitor.py -d 192.168.1.1 -u admin -p secret \
        --device-type cisco_xr --neighbor 10.0.0.1 --max-prefixes 750000

Prerequisites:
    pip install netmiko
    SSH access with at minimum read-only (show) privileges.
    BGP must be configured on the target device.

Exit codes:
    0 - all sessions healthy
    1 - one or more sessions degraded or threshold breached
    2 - connection / authentication failure
"""

import argparse
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException


logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


SUPPORTED_DEVICE_TYPES = ["cisco_ios", "cisco_xe", "cisco_xr", "cisco_nxos"]

BGP_SUMMARY_COMMANDS = {
    "cisco_ios": "show bgp summary",
    "cisco_xe": "show bgp summary",
    "cisco_xr": "show bgp summary",
    "cisco_nxos": "show bgp summary",
}

# Matches neighbor lines in 'show bgp summary' across IOS/XE/XR/NX-OS.
# Columns: Neighbor, V, AS, MsgRcvd, MsgSent, TblVer, InQ, OutQ, Up/Down, State/PfxRcd
_NEIGHBOR_RE = re.compile(
    r"^(?P<neighbor>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"\d+\s+"               # V
    r"(?P<as>\d+)\s+"       # AS
    r"\d+\s+\d+\s+"         # MsgRcvd, MsgSent
    r"\d+\s+\d+\s+\d+\s+"  # TblVer, InQ, OutQ
    r"(?P<updown>\S+)\s+"   # Up/Down
    r"(?P<state>\S+)",      # State or prefix count
    re.MULTILINE,
)


def parse_bgp_summary(output):
    """Return list of neighbor dicts parsed from show bgp summary output."""
    neighbors = []
    for m in _NEIGHBOR_RE.finditer(output):
        state_field = m.group("state")
        try:
            prefix_count = int(state_field)
            state = "Established"
        except ValueError:
            prefix_count = 0
            state = state_field

        neighbors.append(
            {
                "neighbor": m.group("neighbor"),
                "as": m.group("as"),
                "uptime": m.group("updown"),
                "state": state,
                "prefixes_received": prefix_count,
            }
        )
    return neighbors


def check_bgp_sessions(conn, device_type, target_neighbor=None, max_prefixes=None):
    """Fetch and evaluate BGP session health. Returns (neighbors, issues)."""
    command = BGP_SUMMARY_COMMANDS.get(device_type, "show bgp summary")
    log.info("Running: %s", command)
    output = conn.send_command(command, read_timeout=60)

    neighbors = parse_bgp_summary(output)

    if target_neighbor:
        neighbors = [n for n in neighbors if n["neighbor"] == target_neighbor]
        if not neighbors:
            return [], [f"Neighbor {target_neighbor} not found in BGP table"]

    issues = []
    for n in neighbors:
        if n["state"] != "Established":
            issues.append(
                f"Neighbor {n['neighbor']} AS {n['as']} is {n['state']}"
                f" (up/down: {n['uptime']})"
            )
        elif max_prefixes and n["prefixes_received"] > max_prefixes:
            issues.append(
                f"Neighbor {n['neighbor']} prefix count {n['prefixes_received']}"
                f" exceeds limit {max_prefixes}"
            )
    return neighbors, issues


def print_report(neighbors, issues, hostname):
    print(f"\nBGP Session Report — {hostname}")
    print("=" * 64)

    if not neighbors:
        print("No BGP neighbors found.")
        return

    header = f"{'Neighbor':<18} {'AS':<8} {'State':<15} {'Prefixes':>10}  Uptime"
    print(header)
    print("-" * 64)
    for n in neighbors:
        flag = " [!]" if n["state"] != "Established" else ""
        print(
            f"{n['neighbor']:<18} {n['as']:<8} {n['state']:<15}"
            f" {n['prefixes_received']:>10}  {n['uptime']}{flag}"
        )

    print()
    if issues:
        print(f"ISSUES FOUND ({len(issues)}):")
        for issue in issues:
            print(f"  ! {issue}")
    else:
        print(f"All {len(neighbors)} BGP session(s) healthy.")


def build_parser():
    p = argparse.ArgumentParser(
        description="Audit BGP neighbor session health on a network device."
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument(
        "-t", "--device-type",
        default="cisco_ios",
        choices=SUPPORTED_DEVICE_TYPES,
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--neighbor", default=None, help="Filter to a single BGP neighbor IP")
    p.add_argument(
        "--max-prefixes", type=int, default=None,
        help="Alert when received prefix count exceeds this value",
    )
    p.add_argument("--timeout", type=int, default=30, help="Connection timeout seconds")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}@{args.device}: ")

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": password,
        "port": args.port,
        "timeout": args.timeout,
    }

    try:
        log.info("Connecting to %s (%s)", args.device, args.device_type)
        with ConnectHandler(**device_params) as conn:
            hostname = conn.find_prompt().strip("#>")
            neighbors, issues = check_bgp_sessions(
                conn,
                args.device_type,
                target_neighbor=args.neighbor,
                max_prefixes=args.max_prefixes,
            )

        print_report(neighbors, issues, hostname)
        sys.exit(1 if issues else 0)

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(2)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s port %d", args.device, args.port)
        sys.exit(2)
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        sys.exit(2)
```