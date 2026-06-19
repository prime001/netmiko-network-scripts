```python
"""
route_validator.py - Post-change routing table validator

Connects to a network device and verifies that expected routes are present
with the correct next-hop and/or egress interface. Use after routing changes
(static routes, OSPF, BGP) to confirm convergence before closing a change window.

Usage:
    python route_validator.py -d 192.168.1.1 -u admin -p secret \
        --device-type cisco_ios --routes expected_routes.json

    python route_validator.py -d 192.168.1.1 -u admin -p secret \
        --device-type cisco_ios --prefix 10.0.0.0/8 --next-hop 192.168.1.254

Routes JSON format:
    [
        {"prefix": "10.0.0.0/8", "next_hop": "192.168.1.254"},
        {"prefix": "172.16.0.0/12", "interface": "GigabitEthernet0/1"},
        {"prefix": "0.0.0.0/0", "next_hop": "203.0.113.1", "interface": "Gi0/0"}
    ]

Exit codes: 0 = all passed, 1 = error, 2 = one or more routes failed.

Prerequisites:
    pip install netmiko
"""

import argparse
import json
import logging
import re
import sys

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


ROUTE_COMMANDS = {
    "cisco_ios": "show ip route {network}",
    "cisco_xe": "show ip route {network}",
    "cisco_nxos": "show ip route {network}",
    "juniper_junos": "show route {network}",
    "arista_eos": "show ip route {network}",
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Validate routing table entries after a network change"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(ROUTE_COMMANDS.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--routes", metavar="FILE", help="JSON file with expected route entries"
    )
    parser.add_argument(
        "--prefix", help="Single prefix to validate (e.g. 10.0.0.0/8)"
    )
    parser.add_argument("--next-hop", help="Expected next-hop IP for --prefix")
    parser.add_argument(
        "--interface", help="Expected egress interface for --prefix"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="SSH connection timeout in seconds (default: 30)",
    )
    return parser.parse_args()


def load_routes(args):
    if args.routes:
        try:
            with open(args.routes) as fh:
                routes = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            log.error("Cannot read routes file: %s", exc)
            sys.exit(1)
        if not isinstance(routes, list):
            log.error("Routes file must contain a JSON array")
            sys.exit(1)
        return routes

    if args.prefix:
        entry = {"prefix": args.prefix}
        if args.next_hop:
            entry["next_hop"] = args.next_hop
        if args.interface:
            entry["interface"] = args.interface
        return [entry]

    log.error("Specify --routes FILE or --prefix")
    sys.exit(1)


def _interface_present(output, interface):
    """Return True if interface appears in output, accounting for abbreviations."""
    if interface.lower() in output.lower():
        return True
    abbrev = re.sub(r"([A-Za-z]{2})[A-Za-z]+", r"\1", interface)
    return abbrev.lower() in output.lower()


def check_route(output, prefix, next_hop=None, interface=None):
    """Return (passed: bool, reason: str) for one route entry."""
    network = prefix.split("/")[0]
    if network not in output and prefix not in output:
        return False, f"prefix {prefix} not found in routing table"

    if next_hop and next_hop not in output:
        return False, f"expected next-hop {next_hop} not found for {prefix}"

    if interface and not _interface_present(output, interface):
        return False, f"expected interface {interface} not found for {prefix}"

    return True, "OK"


def validate_routes(connection, device_type, routes):
    cmd_template = ROUTE_COMMANDS.get(device_type, "show ip route {network}")
    results = []

    for entry in routes:
        prefix = entry.get("prefix", "").strip()
        if not prefix:
            log.warning("Skipping entry with missing 'prefix': %s", entry)
            continue

        network = prefix.split("/")[0]
        cmd = cmd_template.format(network=network)
        log.debug("Sending: %s", cmd)

        try:
            output = connection.send_command(cmd, read_timeout=30)
        except Exception as exc:
            results.append(
                {"prefix": prefix, "passed": False, "reason": f"command error: {exc}"}
            )
            continue

        passed, reason = check_route(
            output,
            prefix,
            next_hop=entry.get("next_hop"),
            interface=entry.get("interface"),
        )
        results.append({"prefix": prefix, "passed": passed, "reason": reason})

    return results


def main():
    args = parse_args()
    routes = load_routes(args)

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "timeout": args.timeout,
    }

    log.info("Connecting to %s (%s)", args.device, args.device_type)
    try:
        connection = ConnectHandler(**device_params)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.device)
        sys.exit(1)
    except Exception as exc:
        log.error("Connection failed: %s", exc)
        sys.exit(1)

    try:
        results = validate_routes(connection, args.device_type, routes)
    finally:
        connection.disconnect()

    passed = [r for r in results if r["passed"]]
    failed = [r for r in results if not r["passed"]]

    print(f"\nRoute validation results — {args.device}")
    print("-" * 52)
    for r in results:
        tag = "PASS" if r["passed"] else "FAIL"
        print(f"  [{tag}] {r['prefix']:<22} {r['reason']}")
    print("-" * 52)
    print(f"  Total: {len(results)}   Passed: {len(passed)}   Failed: {len(failed)}\n")

    if failed:
        log.warning("%d route(s) failed validation", len(failed))
        sys.exit(2)

    log.info("All %d route(s) validated successfully", len(passed))


if __name__ == "__main__":
    main()
```