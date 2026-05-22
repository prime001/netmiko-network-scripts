mac_port_bounce.py — Locate a device by MAC address and bounce its switchport.

In most NOC tickets you get a host name or IP, not a switch interface. This
script resolves a MAC address (or IP via ARP table) to a specific port, then
performs a shutdown / no-shutdown cycle on that port and confirms it returns
to up/up.

Usage:
    # Bounce by MAC address
    python mac_port_bounce.py --host 10.0.0.1 --username admin --password secret \
        --mac 00:1a:2b:3c:4d:5e

    # Bounce by IP (resolves via ARP table first)
    python mac_port_bounce.py --host 10.0.0.1 --username admin --password secret \
        --ip 192.168.1.42

    # Skip MAC lookup; bounce a known interface directly
    python mac_port_bounce.py --host 10.0.0.1 --username admin --password secret \
        --interface GigabitEthernet0/1 --wait 10

Prerequisites:
    pip install netmiko
    Tested against Cisco IOS / IOS-XE.  For NX-OS change --device-type to
    cisco_nxos and the MAC table regex may need adjustment.
"""

import argparse
import logging
import re
import sys
import time
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)


def normalize_mac(mac: str) -> str:
    return re.sub(r"[.:\-]", "", mac).lower()


def ip_to_mac(conn, ip: str) -> Optional[str]:
    output = conn.send_command(f"show ip arp {ip}")
    match = re.search(r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", output, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def mac_to_port(conn, mac: str) -> Optional[str]:
    norm = normalize_mac(mac)
    output = conn.send_command("show mac address-table")
    for line in output.splitlines():
        if norm in normalize_mac(line):
            tokens = line.split()
            for token in reversed(tokens):
                if re.match(r"[A-Za-z]", token) and "/" in token:
                    return token
    return None


def bounce_interface(conn, interface: str, wait: int) -> None:
    log.info("Shutting down %s", interface)
    conn.send_config_set([f"interface {interface}", "shutdown"])
    log.info("Holding down for %d second(s)", wait)
    time.sleep(wait)
    log.info("Bringing up %s", interface)
    conn.send_config_set([f"interface {interface}", "no shutdown"])


def interface_is_up(conn, interface: str) -> bool:
    output = conn.send_command(f"show interfaces {interface} | include line protocol")
    return bool(re.search(r"line protocol is up", output, re.IGNORECASE))


def wait_for_up(conn, interface: str, timeout: int = 30) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if interface_is_up(conn, interface):
            return True
        time.sleep(3)
    return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Locate a device by MAC/IP and bounce its switchport."
    )
    parser.add_argument("--host", required=True, help="Switch management IP or hostname")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--device-type", default="cisco_ios")
    parser.add_argument("--port", type=int, default=22)

    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--mac", help="Device MAC address (any separator format)")
    target.add_argument("--ip", help="Device IP — resolved to MAC via ARP table")
    target.add_argument("--interface", help="Interface to bounce directly (skips MAC lookup)")

    parser.add_argument(
        "--wait", type=int, default=5, help="Seconds to hold port down (default: 5)"
    )
    parser.add_argument(
        "--verify-timeout", type=int, default=30,
        help="Seconds to wait for port to return up (default: 30)"
    )
    parser.add_argument(
        "--no-verify", action="store_true", help="Skip post-bounce link-up check"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }

    try:
        log.info("Connecting to %s", args.host)
        conn = ConnectHandler(**device)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.host)
        return 1
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        return 1

    try:
        interface = args.interface

        if args.ip:
            log.info("Resolving IP %s to MAC via ARP table", args.ip)
            args.mac = ip_to_mac(conn, args.ip)
            if not args.mac:
                log.error("IP %s not found in ARP table — is the device reachable?", args.ip)
                return 1
            log.info("Resolved %s → MAC %s", args.ip, args.mac)

        if args.mac:
            log.info("Looking up MAC %s in address table", args.mac)
            interface = mac_to_port(conn, args.mac)
            if not interface:
                log.error(
                    "MAC %s not found in address table — device may be inactive or behind a hub",
                    args.mac,
                )
                return 1
            log.info("MAC %s is on interface %s", args.mac, interface)

        bounce_interface(conn, interface, args.wait)

        if not args.no_verify:
            log.info("Waiting up to %ds for %s to return up/up...", args.verify_timeout, interface)
            if wait_for_up(conn, interface, args.verify_timeout):
                log.info("SUCCESS: %s is up/up — bounce complete", interface)
            else:
                log.warning(
                    "Interface %s did not return to up/up within %ds",
                    interface, args.verify_timeout,
                )
                return 2
    finally:
        conn.disconnect()

    return 0


if __name__ == "__main__":
    sys.exit(main())