```python
"""
BGP Neighbor Health Check — 017_bgp_health_check.py

Polls BGP neighbor state on Cisco IOS/IOS-XE and NX-OS devices via Netmiko,
flags non-Established sessions, and reports prefix counts with optional
threshold alerting.

Usage:
    python 017_bgp_health_check.py -d 10.0.0.1 -u admin -p secret
    python 017_bgp_health_check.py -d 10.0.0.1 -u admin -p secret \
        --device-type cisco_nxos --min-prefixes 100 --output bgp_report.txt

Prerequisites:
    pip install netmiko
    Device must have SSH enabled and BGP configured.
"""

import argparse
import logging
import sys
import re
from datetime import datetime
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

BGP_COMMANDS = {
    "cisco_ios": "show ip bgp summary",
    "cisco_xe": "show ip bgp summary",
    "cisco_nxos": "show bgp ipv4 unicast summary",
}

# Matches neighbor lines: IP  4  AS  uptime  prefixes_rcvd (or "Idle"/"Active")
_NEIGHBOR_RE = re.compile(
    r"^(?P<neighbor>\d+\.\d+\.\d+\.\d+)\s+\d\s+(?P<as>\d+)"
    r"\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<state_or_pfx>\S+)",
    re.MULTILINE,
)


def parse_bgp_summary(output):
    neighbors = []
    for m in _NEIGHBOR_RE.finditer(output):
        raw = m.group("state_or_pfx")
        try:
            pfx = int(raw)
            state = "Established"
        except ValueError:
            pfx = 0
            state = raw
        neighbors.append({
            "neighbor": m.group("neighbor"),
            "remote_as": m.group("as"),
            "state": state,
            "prefixes_received": pfx,
        })
    return neighbors


def check_device(host, username, password, device_type, min_prefixes):
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
    }
    issues = []
    neighbors = []

    try:
        log.info("Connecting to %s (%s)", host, device_type)
        with ConnectHandler(**device) as conn:
            cmd = BGP_COMMANDS.get(device_type, "show ip bgp summary")
            output = conn.send_command(cmd, read_timeout=30)
        neighbors = parse_bgp_summary(output)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", host)
        issues.append("AUTH_FAILURE")
        return neighbors, issues
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", host)
        issues.append("TIMEOUT")
        return neighbors, issues
    except Exception as exc:
        log.error("Unexpected error for %s: %s", host, exc)
        issues.append(f"ERROR: {exc}")
        return neighbors, issues

    for n in neighbors:
        if n["state"] != "Established":
            issues.append(f"NEIGHBOR_DOWN {n['neighbor']} AS{n['remote_as']} ({n['state']})")
        elif min_prefixes and n["prefixes_received"] < min_prefixes:
            issues.append(
                f"LOW_PREFIXES {n['neighbor']} AS{n['remote_as']}"
                f" ({n['prefixes_received']} < {min_prefixes})"
            )

    return neighbors, issues


def format_report(host, neighbors, issues, elapsed_ms):
    lines = [
        f"BGP Health Report — {host}",
        f"Timestamp : {datetime.utcnow().isoformat()}Z",
        f"Duration  : {elapsed_ms:.0f} ms",
        f"Neighbors : {len(neighbors)}",
        "",
    ]
    if neighbors:
        lines.append(f"{'Neighbor':<18} {'Remote AS':<12} {'State':<14} {'Pfx Rcvd':>10}")
        lines.append("-" * 56)
        for n in neighbors:
            lines.append(
                f"{n['neighbor']:<18} {n['remote_as']:<12}"
                f" {n['state']:<14} {n['prefixes_received']:>10}"
            )
    else:
        lines.append("  No BGP neighbors parsed.")

    lines.append("")
    if issues:
        lines.append(f"ISSUES ({len(issues)}):")
        for iss in issues:
            lines.append(f"  ! {iss}")
    else:
        lines.append("STATUS: OK — all neighbors Established")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="BGP neighbor health check via Netmiko"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(BGP_COMMANDS.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument(
        "--min-prefixes",
        type=int,
        default=0,
        metavar="N",
        help="Alert if an Established neighbor advertises fewer than N prefixes",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Write report to FILE in addition to stdout",
    )
    args = parser.parse_args()

    t_start = datetime.utcnow()
    neighbors, issues = check_device(
        args.device, args.username, args.password,
        args.device_type, args.min_prefixes,
    )
    elapsed = (datetime.utcnow() - t_start).total_seconds() * 1000

    report = format_report(args.device, neighbors, issues, elapsed)
    print(report)

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(report + "\n")
        log.info("Report written to %s", args.output)

    sys.exit(1 if issues else 0)


if __name__ == "__main__":
    main()
```