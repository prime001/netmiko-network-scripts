```python
"""
bgp_neighbor_health.py - BGP neighbor state and prefix health checker

Purpose:
    Connects to a Cisco IOS/IOS-XE router via SSH and audits BGP neighbor
    health: session state, prefixes received, and optional prefix-count thresholds.
    Exits non-zero when issues are detected, making it suitable for monitoring
    integration or pre/post-change validation pipelines.

Usage:
    python bgp_neighbor_health.py -d 192.168.1.1 -u admin
    python bgp_neighbor_health.py -d 192.168.1.1 -u admin -p secret --min-prefixes 100
    python bgp_neighbor_health.py -d 192.168.1.1 -u admin --neighbor 10.0.0.2

Prerequisites:
    pip install netmiko
    SSH access to the target device with privilege level sufficient to run
    'show ip bgp summary'.
"""

import argparse
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import NetMikoAuthenticationException, NetMikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def parse_bgp_summary(output):
    """Return a list of neighbor dicts parsed from 'show ip bgp summary' output."""
    neighbors = []
    # Matches: neighbor-IP  V  remote-AS  MsgRcvd  MsgSent  TblVer  InQ  OutQ  Up/Down  State/PfxRcd
    pattern = re.compile(
        r"^(\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"\d+\s+"
        r"(\d+)\s+"
        r"\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+"
        r"(\S+)\s+"
        r"(\S+)",
        re.MULTILINE,
    )
    for m in pattern.finditer(output):
        neighbor_ip, remote_as, updown, state_or_pfx = m.groups()
        try:
            prefixes_received = int(state_or_pfx)
            state = "Established"
        except ValueError:
            prefixes_received = 0
            state = state_or_pfx
        neighbors.append(
            {
                "neighbor": neighbor_ip,
                "remote_as": remote_as,
                "updown": updown,
                "state": state,
                "prefixes_received": prefixes_received,
            }
        )
    return neighbors


def check_bgp_health(connection, target_neighbor=None, min_prefixes=0):
    """Return (results, issues) after checking BGP neighbor health."""
    log.info("Running 'show ip bgp summary'")
    output = connection.send_command("show ip bgp summary", read_timeout=30)

    if "BGP not active" in output or output.strip().startswith("%"):
        return [], ["BGP is not active on this device"]

    neighbors = parse_bgp_summary(output)
    if not neighbors:
        return [], ["No BGP neighbors parsed — check device type or privilege level"]

    if target_neighbor:
        neighbors = [n for n in neighbors if n["neighbor"] == target_neighbor]
        if not neighbors:
            return [], [f"Neighbor {target_neighbor} not found in BGP table"]

    issues = []
    results = []
    for n in neighbors:
        flags = []
        if n["state"] != "Established":
            flags.append(f"state={n['state']}")
        elif min_prefixes and n["prefixes_received"] < min_prefixes:
            flags.append(
                f"prefixes_received={n['prefixes_received']} below threshold={min_prefixes}"
            )
        status = "DOWN" if n["state"] != "Established" else ("WARN" if flags else "OK")
        if flags:
            issues.append(f"{n['neighbor']} AS{n['remote_as']}: {'; '.join(flags)}")
        results.append({**n, "status": status})

    return results, issues


def print_report(results, issues):
    col = f"{'Neighbor':<18} {'AS':<8} {'Up/Down':<14} {'State':<14} {'PfxRcvd':<10} Status"
    print("\n" + col)
    print("-" * len(col))
    for r in results:
        print(
            f"{r['neighbor']:<18} {r['remote_as']:<8} {r['updown']:<14} "
            f"{r['state']:<14} {r['prefixes_received']:<10} {r['status']}"
        )
    if issues:
        print(f"\n[!] {len(issues)} issue(s) detected:")
        for issue in issues:
            print(f"    - {issue}")
    else:
        print(f"\n[+] All {len(results)} BGP neighbor(s) healthy.")


def build_args():
    p = argparse.ArgumentParser(
        description="Audit BGP neighbor health on a Cisco IOS/IOS-XE device."
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--neighbor", default=None, help="Limit check to a single neighbor IP")
    p.add_argument(
        "--min-prefixes", type=int, default=0, metavar="N",
        help="Warn if an established neighbor advertises fewer than N prefixes",
    )
    p.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return p.parse_args()


if __name__ == "__main__":
    args = build_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}@{args.device}: ")

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": password,
        "port": args.port,
    }

    log.info("Connecting to %s", args.device)
    try:
        with ConnectHandler(**device_params) as conn:
            results, issues = check_bgp_health(conn, args.neighbor, args.min_prefixes)
    except NetMikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(2)
    except NetMikoTimeoutException:
        log.error("Connection timed out to %s", args.device)
        sys.exit(3)
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        sys.exit(4)

    if not results and not issues:
        log.warning("No results returned from device.")
        sys.exit(1)

    print_report(results, issues)
    sys.exit(1 if issues else 0)
```