bgp_session_monitor.py - BGP neighbor session state checker using netmiko.

Purpose:
    Connect to one or more Cisco IOS/IOS-XE/NX-OS devices and report the
    state of all BGP neighbor sessions. Flags any session not in the
    Established state and exits with code 1 if issues are found, making it
    suitable for integration with monitoring systems (Nagios, Zabbix, etc.).

Usage:
    python bgp_session_monitor.py -H 192.168.1.1 -u admin -p secret
    python bgp_session_monitor.py -H 192.168.1.1 192.168.1.2 -u admin
    python bgp_session_monitor.py -H 192.168.1.1 -u admin --vrf MGMT --json

Prerequisites:
    pip install netmiko
    SSH access to target device(s) with at least privilege level 1.
    BGP must be configured on the device.
"""

import argparse
import json
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def parse_bgp_summary(output):
    """Parse 'show ip bgp summary' output into neighbor dicts.

    In IOS BGP summary, established neighbors show a prefix count (integer)
    in the State/PfxRcd column; non-established show the FSM state name.
    """
    neighbors = []
    pattern = re.compile(
        r"^(\d{1,3}(?:\.\d{1,3}){3})\s+"
        r"(\d+)\s+"
        r"(\d+)\s+"
        r"\d+\s+\d+\s+\d+\s+\d+\s+"
        r"(\S+)\s+"
        r"(\S+)$"
    )
    for line in output.splitlines():
        match = pattern.match(line.strip())
        if match:
            neighbor, version, asn, up_down, state_or_pfx = match.groups()
            established = state_or_pfx.lstrip("(").rstrip(")").isdigit()
            neighbors.append({
                "neighbor": neighbor,
                "as": int(asn),
                "uptime": up_down,
                "state": "Established" if established else state_or_pfx,
                "prefixes_received": int(state_or_pfx) if established else None,
                "established": established,
            })
    return neighbors


def check_bgp_sessions(device_params, vrf=None):
    """Connect to a device and return (neighbors, error_string)."""
    host = device_params["host"]
    cmd = "show ip bgp summary"
    if vrf:
        cmd = f"show ip bgp vrf {vrf} summary"

    try:
        logger.info("Connecting to %s", host)
        with ConnectHandler(**device_params) as conn:
            output = conn.send_command(cmd, read_timeout=30)
        logger.info("Disconnected from %s", host)
    except NetmikoAuthenticationException:
        return None, f"Authentication failed for {host}"
    except NetmikoTimeoutException:
        return None, f"Connection timed out for {host}"
    except Exception as exc:
        logger.error("Unexpected error on %s: %s", host, exc)
        return None, str(exc)

    if any(marker in output for marker in ("% Invalid", "% BGP not active", "not running")):
        return [], None

    return parse_bgp_summary(output), None


def render_text(host, neighbors, error):
    """Print a human-readable report for one device."""
    if error:
        print(f"[ERROR] {host}: {error}")
        return

    if not neighbors:
        print(f"[INFO]  {host}: BGP not active or no neighbors configured")
        return

    down = [n for n in neighbors if not n["established"]]
    tag = "OK  " if not down else "WARN"
    print(f"[{tag}] {host}: {len(neighbors) - len(down)}/{len(neighbors)} sessions established")

    for n in neighbors:
        pfx = f"pfx={n['prefixes_received']}" if n["established"] else f"state={n['state']}"
        alert = "" if n["established"] else "  <-- DOWN"
        print(f"       {n['neighbor']:<18s}  AS {n['as']:<8d}  uptime={n['uptime']:<12s}  {pfx}{alert}")


def build_parser():
    p = argparse.ArgumentParser(
        description="Check BGP neighbor session states via SSH/netmiko.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-H", "--hosts", nargs="+", required=True, metavar="HOST",
                   help="Device IP address(es) or hostname(s)")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None,
                   help="SSH password (prompted securely if omitted)")
    p.add_argument("--enable-secret", default=None, metavar="SECRET",
                   help="Enable/privilege secret if required")
    p.add_argument("--device-type", default="cisco_ios",
                   choices=["cisco_ios", "cisco_xe", "cisco_nxos"],
                   help="Netmiko device type (default: cisco_ios)")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=15,
                   help="Connection timeout in seconds (default: 15)")
    p.add_argument("--vrf", default=None,
                   help="BGP VRF name (omit for global routing table)")
    p.add_argument("--json", action="store_true", dest="use_json",
                   help="Emit results as JSON instead of plain text")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Enable debug-level SSH logging")
    return p


def main():
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    password = args.password or getpass(f"Password for {args.username}@{args.hosts[0]}: ")

    all_results = {}
    exit_code = 0

    for host in args.hosts:
        device_params = {
            "device_type": args.device_type,
            "host": host,
            "username": args.username,
            "password": password,
            "port": args.port,
            "conn_timeout": args.timeout,
        }
        if args.enable_secret:
            device_params["secret"] = args.enable_secret

        neighbors, error = check_bgp_sessions(device_params, vrf=args.vrf)

        if error or (neighbors and any(not n["established"] for n in neighbors)):
            exit_code = 1

        if args.use_json:
            all_results[host] = {"error": error, "neighbors": neighbors or []}
        else:
            render_text(host, neighbors, error)

    if args.use_json:
        print(json.dumps(all_results, indent=2))

    sys.exit(exit_code)


if __name__ == "__main__":
    main()