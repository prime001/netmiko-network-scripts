```python
"""
Port Bounce with Pre/Post State Verification
=============================================
Bounces one or more switchports and verifies interface state before and after.
Captures MAC address table entries and error-disabled status to confirm
the port came back clean. Designed for field use during client site visits
or remote troubleshooting sessions.

Usage:
    python 021_port_bounce.py -H 10.0.0.1 -u admin -p secret -i GigabitEthernet0/1
    python 021_port_bounce.py -H 10.0.0.1 -u admin -p secret -i Gi0/1 Gi0/2 Gi0/3
    python 021_port_bounce.py -H 10.0.0.1 -u admin -p secret -i Gi0/1 --delay 10 --dry-run

Prerequisites:
    pip install netmiko
    Tested against: Cisco IOS, IOS-XE
    Requires privilege level 15 (enable access or direct priv-exec login)
"""

import argparse
import logging
import re
import sys
import time
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def parse_interface_state(output: str, interface: str) -> dict:
    """Extract link status and protocol state from 'show interface' output."""
    state = {"line": "unknown", "protocol": "unknown", "err_disabled": False}
    pattern = re.compile(
        r"^\S.*?is\s+(\S+(?:\s+\S+)?),\s+line protocol is\s+(\S+)", re.MULTILINE
    )
    match = pattern.search(output)
    if match:
        state["line"] = match.group(1).strip(",")
        state["protocol"] = match.group(2).strip(",")
        state["err_disabled"] = "err-disabled" in match.group(1).lower()
    return state


def get_mac_count(connection, interface: str) -> int:
    """Return number of MACs learned on the interface."""
    output = connection.send_command(
        f"show mac address-table interface {interface}",
        expect_string=r"#",
    )
    lines = [
        l for l in output.splitlines()
        if re.match(r"\s+\d+\s+[0-9a-f.]{14}", l, re.IGNORECASE)
    ]
    return len(lines)


def bounce_interface(connection, interface: str, delay: int, dry_run: bool) -> bool:
    """Shut/no-shut the interface. Returns True if post-state is up/up."""
    log.info("[%s] Capturing pre-bounce state ...", interface)
    pre_output = connection.send_command(f"show interface {interface}")
    pre_state = parse_interface_state(pre_output, interface)
    pre_macs = get_mac_count(connection, interface)

    log.info(
        "[%s] PRE  — line: %s  protocol: %s  MACs: %d%s",
        interface,
        pre_state["line"],
        pre_state["protocol"],
        pre_macs,
        "  [ERR-DISABLED]" if pre_state["err_disabled"] else "",
    )

    if dry_run:
        log.info("[%s] DRY-RUN: skipping shut/no-shut", interface)
        return True

    log.info("[%s] Sending: shutdown", interface)
    connection.send_config_set([f"interface {interface}", "shutdown"])
    time.sleep(2)

    log.info("[%s] Sending: no shutdown (delay: %ds)", interface, delay)
    connection.send_config_set([f"interface {interface}", "no shutdown"])
    time.sleep(delay)

    log.info("[%s] Capturing post-bounce state ...", interface)
    post_output = connection.send_command(f"show interface {interface}")
    post_state = parse_interface_state(post_output, interface)
    post_macs = get_mac_count(connection, interface)

    success = (
        post_state["line"] in ("up", "connected")
        and post_state["protocol"] in ("up", "connected")
        and not post_state["err_disabled"]
    )

    log.info(
        "[%s] POST — line: %s  protocol: %s  MACs: %d  result: %s",
        interface,
        post_state["line"],
        post_state["protocol"],
        post_macs,
        "OK" if success else "FAIL",
    )

    if post_state["err_disabled"]:
        log.error("[%s] Port is still err-disabled after bounce.", interface)

    return success


def main():
    parser = argparse.ArgumentParser(
        description="Bounce switchport(s) with pre/post state verification."
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    parser.add_argument(
        "-i", "--interfaces", nargs="+", required=True,
        metavar="INTF", help="Interface(s) to bounce, e.g. Gi0/1 Gi0/2",
    )
    parser.add_argument(
        "--delay", type=int, default=5,
        help="Seconds to wait after no-shut before verifying (default: 5)",
    )
    parser.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show pre-state only; skip the actual shut/no-shut",
    )
    args = parser.parse_args()

    password = args.password or getpass(f"Password for {args.username}@{args.host}: ")

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": password,
        "timeout": 30,
    }

    try:
        log.info("Connecting to %s ...", args.host)
        with ConnectHandler(**device) as conn:
            conn.enable()
            log.info("Connected. Hostname: %s", conn.find_prompt().rstrip("#>"))

            results = {}
            for intf in args.interfaces:
                results[intf] = bounce_interface(conn, intf, args.delay, args.dry_run)

        log.info("--- Summary ---")
        all_ok = True
        for intf, ok in results.items():
            status = "OK" if ok else "FAIL"
            log.info("  %-30s %s", intf, status)
            if not ok:
                all_ok = False

        sys.exit(0 if all_ok else 1)

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(2)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        sys.exit(2)
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        sys.exit(2)


if __name__ == "__main__":
    main()
```