The user's instruction "Output ONLY the script content, no markdown fences, no explanation" takes precedence over the brainstorming workflow. The requirements are fully specified — proceeding directly to output.

"""
mac_aware_port_bounce.py — Port bounce with before/after MAC address verification.

Captures MAC addresses learned on an interface, performs a shutdown/no-shutdown
cycle, then confirms all known end-devices reconnect within a configurable window.
Useful when troubleshooting client connectivity: you bounce the port without losing
track of which devices were expected to return.

Usage:
    python mac_aware_port_bounce.py -d 192.168.1.1 -u admin -i GigabitEthernet0/1
    python mac_aware_port_bounce.py -d 10.0.0.1 -u admin -i Gi0/2 --wait 15 --timeout 120 -v

Prerequisites:
    pip install netmiko
    SSH access with privilege level 15 (or supply --enable-password)
"""

import argparse
import logging
import sys
import time
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def get_port_macs(conn, interface):
    """Return set of MAC addresses currently learned on the interface."""
    output = conn.send_command(f"show mac address-table interface {interface}")
    macs = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and len(parts[1]) == 14 and "." in parts[1]:
            macs.add(parts[1].lower())
    return macs


def is_port_up(conn, interface):
    output = conn.send_command(
        f"show interface {interface} | include line protocol"
    )
    return "line protocol is up" in output


def wait_for_link(conn, interface, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_port_up(conn, interface):
            return True
        time.sleep(3)
    return False


def bounce_port(conn, interface, hold_seconds):
    log.info("Shutting down %s", interface)
    conn.send_config_set([f"interface {interface}", "shutdown"])
    time.sleep(hold_seconds)
    log.info("Re-enabling %s", interface)
    conn.send_config_set([f"interface {interface}", "no shutdown"])


def verify_macs_returned(conn, interface, expected, timeout):
    if not expected:
        log.info("No MACs were present before bounce — skipping MAC verification")
        return True, set()
    deadline = time.time() + timeout
    while time.time() < deadline:
        current = get_port_macs(conn, interface)
        missing = expected - current
        if not missing:
            return True, set()
        log.debug("Still waiting for: %s", missing)
        time.sleep(5)
    return False, expected - get_port_macs(conn, interface)


def build_args():
    p = argparse.ArgumentParser(
        description="Bounce a switch port and verify end-device MACs reappear."
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    p.add_argument(
        "-e", "--enable-password", dest="enable_password",
        help="Enable password if needed"
    )
    p.add_argument("-i", "--interface", required=True,
                   help="Interface to bounce (e.g. Gi0/1, Ethernet1/3)")
    p.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)"
    )
    p.add_argument(
        "--wait", type=int, default=10, metavar="SEC",
        help="Seconds to hold the port down (default: 10)"
    )
    p.add_argument(
        "--timeout", type=int, default=90, metavar="SEC",
        help="Max seconds to wait for port and MACs to return (default: 90)"
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p.parse_args()


def main():
    args = build_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}@{args.device}: ")

    params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": password,
        "timeout": 30,
    }
    if args.enable_password:
        params["secret"] = args.enable_password

    log.info("Connecting to %s", args.device)
    try:
        conn = ConnectHandler(**params)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.device)
        sys.exit(1)

    if args.enable_password:
        conn.enable()

    try:
        macs_before = get_port_macs(conn, args.interface)
        log.info(
            "MACs on %s before bounce: %s",
            args.interface,
            macs_before if macs_before else "(none)",
        )

        bounce_port(conn, args.interface, args.wait)
        t_bounce = time.time()

        log.info("Waiting for link on %s (timeout %ds)...", args.interface, args.timeout)
        if not wait_for_link(conn, args.interface, args.timeout):
            log.error(
                "FAIL: %s did not come up within %ds",
                args.interface, args.timeout,
            )
            sys.exit(1)

        link_elapsed = int(time.time() - t_bounce)
        log.info("Link restored on %s after %ds", args.interface, link_elapsed)

        ok, missing = verify_macs_returned(
            conn, args.interface, macs_before, args.timeout
        )
        total_elapsed = int(time.time() - t_bounce)

        if not ok:
            log.warning(
                "WARN: %d MAC(s) did not reappear within %ds: %s",
                len(missing), args.timeout, missing,
            )
            sys.exit(2)

        log.info(
            "OK: bounce complete — %d/%d MAC(s) verified on %s in %ds",
            len(macs_before), len(macs_before), args.interface, total_elapsed,
        )
    finally:
        conn.disconnect()


if __name__ == "__main__":
    main()