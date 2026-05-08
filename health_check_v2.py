```python
"""
bgp_monitor.py — BGP Neighbor State Monitor

Purpose:
    Connects to a router via SSH (Netmiko) and inspects all BGP neighbor
    sessions. Reports session state, uptime, and received prefix counts.
    Flags sessions that are not Established or fall below a prefix threshold.
    Exits non-zero when issues are found so it can drive cron alerts or
    monitoring pipelines.

Usage:
    python bgp_monitor.py -d 10.0.0.1 -u admin -p secret
    python bgp_monitor.py -d 10.0.0.1 -u admin --min-prefixes 5 --timeout 30
    python bgp_monitor.py -d 10.0.0.1 -u admin --device-type cisco_ios_xe -v

Prerequisites:
    pip install netmiko

    SSH must be enabled on the target device.
    The account needs at minimum read access to 'show ip bgp summary'.
"""

import argparse
import getpass
import logging
import re
import sys

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logger = logging.getLogger(__name__)

# Matches a neighbor row in 'show ip bgp summary' output.
# Groups: neighbor_ip, remote_as, up_down, state_or_prefix_count
_NEIGHBOR_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+"   # neighbor IP
    r"\d+\s+"                            # BGP version
    r"(\d+)\s+"                          # remote AS
    r"\S+\s+\S+\s+\S+\s+\S+\s+"        # MsgRcvd MsgSent TblVer InQ
    r"\S+\s+"                            # OutQ
    r"(\S+)\s+"                          # Up/Down
    r"(\S+)$",                           # State/PfxRcd
    re.MULTILINE,
)


def parse_bgp_summary(output: str) -> list:
    neighbors = []
    for m in _NEIGHBOR_RE.finditer(output):
        ip, remote_as, updown, state_or_pfx = m.groups()
        try:
            prefixes = int(state_or_pfx)
            state = "Established"
        except ValueError:
            prefixes = 0
            state = state_or_pfx
        neighbors.append(
            {"ip": ip, "as": remote_as, "updown": updown,
             "state": state, "prefixes": prefixes}
        )
    return neighbors


def collect_bgp(device_params: dict) -> str:
    try:
        with ConnectHandler(**device_params) as conn:
            logger.info("Connected to %s", device_params["host"])
            return conn.send_command("show ip bgp summary", read_timeout=60)
    except AuthenticationException:
        logger.error("Authentication failed for %s", device_params["host"])
        sys.exit(2)
    except NetmikoTimeoutException:
        logger.error("Connection timed out to %s", device_params["host"])
        sys.exit(3)


def evaluate(neighbors: list, min_prefixes: int) -> int:
    issues = 0
    for n in neighbors:
        if n["state"] != "Established":
            logger.warning(
                "FAIL  %s AS %s — session %s", n["ip"], n["as"], n["state"]
            )
            issues += 1
        elif n["prefixes"] < min_prefixes:
            logger.warning(
                "WARN  %s AS %s — only %d prefix(es) (min: %d)",
                n["ip"], n["as"], n["prefixes"], min_prefixes,
            )
            issues += 1
        else:
            logger.info(
                "OK    %s AS %s — %s up, %d prefix(es)",
                n["ip"], n["as"], n["updown"], n["prefixes"],
            )
    return issues


def print_table(neighbors: list, host: str) -> None:
    print(f"\nBGP Summary  —  {host}")
    print(f"{'Neighbor':<18} {'Remote AS':<12} {'Up/Down':<12} {'State':<16} {'Pfx':>6}")
    print("─" * 66)
    for n in neighbors:
        print(
            f"{n['ip']:<18} {n['as']:<12} {n['updown']:<12} "
            f"{n['state']:<16} {n['prefixes']:>6}"
        )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="BGP neighbor state monitor — detects down sessions and low prefix counts"
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    p.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)"
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--timeout", type=int, default=20,
        help="Connection timeout in seconds (default: 20)"
    )
    p.add_argument(
        "--min-prefixes", type=int, default=1,
        help="Minimum prefix count per Established neighbor before flagging (default: 1)"
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


def main() -> None:
    args = build_parser().parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
    )

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.device}: "
    )

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": password,
        "port": args.port,
        "conn_timeout": args.timeout,
    }

    raw = collect_bgp(device_params)
    neighbors = parse_bgp_summary(raw)

    if not neighbors:
        logger.warning("No BGP neighbors found — verify BGP is running on %s", args.device)
        sys.exit(0)

    print_table(neighbors, args.device)
    issues = evaluate(neighbors, args.min_prefixes)

    if issues:
        print(f"\n[!] {issues} issue(s) detected across {len(neighbors)} BGP neighbor(s)")
        sys.exit(1)

    print(f"\n[+] All {len(neighbors)} BGP neighbor(s) healthy")


if __name__ == "__main__":
    main()
```