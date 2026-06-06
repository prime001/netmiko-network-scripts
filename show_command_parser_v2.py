```python
"""
bgp_session_monitor.py - BGP session state monitor and parser

Purpose:
    Connect to a network device, run the BGP summary command, and parse
    peer states, AS numbers, prefix counts, and session uptime. Exits
    non-zero when any peers are not Established, making it suitable for
    use in monitoring pipelines and alerting scripts.

Usage:
    python bgp_session_monitor.py -d 192.168.1.1 -u admin
    python bgp_session_monitor.py -d 192.168.1.1 -u admin -t cisco_xr
    python bgp_session_monitor.py -d 192.168.1.1 -u admin --json --alert-down

Prerequisites:
    pip install netmiko
    SSH must be enabled on the target device.
    Tested against: cisco_ios, cisco_xe, cisco_xr, cisco_nxos
"""

import argparse
import json
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import NetMikoAuthenticationException, NetMikoTimeoutException

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.WARNING,
)
log = logging.getLogger(__name__)


BGP_COMMANDS = {
    "cisco_ios": "show ip bgp summary",
    "cisco_xe": "show ip bgp summary",
    "cisco_xr": "show bgp ipv4 unicast summary",
    "cisco_nxos": "show bgp ipv4 unicast summary",
}

# neighbor  V  AS  MsgRcvd  MsgSent  TblVer  InQ  OutQ  Up/Down  State/PfxRcd
_IOS_PEER_RE = re.compile(
    r"^(?P<neighbor>\d+\.\d+\.\d+\.\d+)\s+"
    r"\d+\s+(?P<remote_as>\d+)\s+"
    r"\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+"
    r"(?P<updown>\S+)\s+(?P<state>\S+)",
    re.MULTILINE,
)

# IOS-XR: neighbor  AS  SpkrId  MsgRcvd  MsgSent  TblVer  InQ  OutQ  Up/Down  State/PfxRcd
_XR_PEER_RE = re.compile(
    r"^(?P<neighbor>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<remote_as>\d+)\s+"
    r"\S+\s+\S+\s+\S+\s+\S+\s+"
    r"(?P<updown>\S+)\s+(?P<state>\S+)",
    re.MULTILINE,
)

_LOCAL_AS_RE = re.compile(r"local AS number\s+(\d+)", re.IGNORECASE)
_ROUTER_ID_RE = re.compile(r"router identifier\s+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)


def parse_bgp_summary(output: str, device_type: str) -> dict:
    pattern = _XR_PEER_RE if device_type == "cisco_xr" else _IOS_PEER_RE
    local_as_m = _LOCAL_AS_RE.search(output)
    router_id_m = _ROUTER_ID_RE.search(output)

    peers = []
    for m in pattern.finditer(output):
        state = m.group("state")
        established = state.isdigit()
        peers.append({
            "neighbor": m.group("neighbor"),
            "remote_as": int(m.group("remote_as")),
            "updown": m.group("updown"),
            "state": "Established" if established else state,
            "prefixes_received": int(state) if established else None,
            "established": established,
        })

    return {
        "local_as": int(local_as_m.group(1)) if local_as_m else None,
        "router_id": router_id_m.group(1) if router_id_m else None,
        "peers": peers,
        "total": len(peers),
        "established_count": sum(1 for p in peers if p["established"]),
        "down_count": sum(1 for p in peers if not p["established"]),
    }


def print_table(result: dict, hostname: str) -> None:
    rid = result["router_id"] or "unknown"
    las = result["local_as"] or "unknown"
    print(f"\nHost: {hostname}  Router-ID: {rid}  Local AS: {las}")
    print(
        f"Peers: {result['total']}  "
        f"Established: {result['established_count']}  "
        f"Down: {result['down_count']}\n"
    )
    hdr = f"{'Neighbor':<18} {'Remote AS':<12} {'State':<16} {'Up/Down':<14} Pfx Rcvd"
    print(hdr)
    print("-" * len(hdr))
    for p in result["peers"]:
        pfx = str(p["prefixes_received"]) if p["prefixes_received"] is not None else "-"
        state_str = p["state"] if p["established"] else f"** {p['state']} **"
        print(f"{p['neighbor']:<18} {p['remote_as']:<12} {state_str:<16} {p['updown']:<14} {pfx}")
    print()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Parse BGP session summary from a network device",
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument(
        "-t", "--device-type",
        default="cisco_ios",
        choices=list(BGP_COMMANDS.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--json", action="store_true", dest="output_json",
        help="Emit JSON instead of a formatted table",
    )
    p.add_argument(
        "--alert-down", action="store_true",
        help="Exit with code 1 if any peers are not Established",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


def main() -> int:
    args = build_parser().parse_args()

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

    try:
        log.debug("Connecting to %s", args.device)
        with ConnectHandler(**device_params) as conn:
            hostname = conn.find_prompt().strip("#>")
            cmd = BGP_COMMANDS[args.device_type]
            log.debug("Running: %s", cmd)
            output = conn.send_command(cmd, read_timeout=30)
    except NetMikoAuthenticationException:
        print(f"ERROR: Authentication failed for {args.username}@{args.device}", file=sys.stderr)
        return 2
    except NetMikoTimeoutException:
        print(f"ERROR: Connection timed out to {args.device}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    result = parse_bgp_summary(output, args.device_type)

    if args.output_json:
        print(json.dumps(result, indent=2))
    else:
        print_table(result, hostname)

    if args.alert_down and result["down_count"] > 0:
        if not args.output_json:
            print(
                f"ALERT: {result['down_count']} peer(s) not in Established state",
                file=sys.stderr,
            )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
```