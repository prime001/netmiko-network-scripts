```python
"""
mac_verified_port_bounce.py — Port bounce with pre/post MAC address table capture.

Shuts an interface, waits for the hold-down timer, re-enables it, then verifies
that expected MAC addresses relearned within a configurable timeout.  Unlike a
plain shut/no-shut this gives you hard evidence that end-devices reconnected —
useful for confirming loop isolation, STP topology changes, or 802.1X reauthentication.

Usage:
    python mac_verified_port_bounce.py -d 10.0.0.1 -u admin -p secret \
        -i GigabitEthernet0/1 --expected-macs aa:bb:cc:dd:ee:ff

Prerequisites:
    pip install netmiko
    Tested against Cisco IOS / IOS-XE.  Adjust mac_command for other vendors.
"""

import argparse
import logging
import sys
import time

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def get_mac_table(conn, interface):
    """Return a set of MAC addresses currently learned on *interface*."""
    short = interface.replace("GigabitEthernet", "Gi") \
                     .replace("FastEthernet", "Fa") \
                     .replace("TenGigabitEthernet", "Te") \
                     .replace("FortyGigabitEthernet", "Fo") \
                     .replace("HundredGigE", "Hu")
    output = conn.send_command(f"show mac address-table interface {short}")
    macs = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and "." in parts[1]:
            raw = parts[1].replace(".", "")
            formatted = ":".join(raw[i:i+2] for i in range(0, 12, 2))
            macs.add(formatted.lower())
    return macs


def bounce_interface(conn, interface, hold_down):
    """Shut the interface, wait *hold_down* seconds, then re-enable it."""
    log.info("Shutting %s", interface)
    conn.send_config_set([f"interface {interface}", "shutdown"])

    log.info("Holding for %d seconds", hold_down)
    time.sleep(hold_down)

    log.info("Re-enabling %s", interface)
    conn.send_config_set([f"interface {interface}", "no shutdown"])


def wait_for_macs(conn, interface, expected, timeout, poll_interval=5):
    """Poll the MAC table until *expected* MACs appear or *timeout* expires."""
    if not expected:
        return True, set()

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = get_mac_table(conn, interface)
        found = expected & current
        missing = expected - current
        if not missing:
            return True, set()
        log.info("Waiting — found %d/%d expected MACs (%s still missing)",
                 len(found), len(expected), ", ".join(sorted(missing)))
        time.sleep(poll_interval)

    return False, expected - get_mac_table(conn, interface)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Bounce a switch port and verify MAC relearning.",
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("-s", "--secret", default="", help="Enable secret (if needed)")
    parser.add_argument("-i", "--interface", required=True,
                        help="Interface to bounce, e.g. GigabitEthernet0/1")
    parser.add_argument("--device-type", default="cisco_ios",
                        help="Netmiko device type (default: cisco_ios)")
    parser.add_argument("--hold-down", type=int, default=10,
                        help="Seconds to keep interface shut (default: 10)")
    parser.add_argument("--verify-timeout", type=int, default=60,
                        help="Seconds to wait for MACs to relearn (default: 60)")
    parser.add_argument("--expected-macs", nargs="*", default=[],
                        metavar="MAC",
                        help="MAC addresses that must reappear after bounce "
                             "(format: aa:bb:cc:dd:ee:ff)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show pre-bounce MAC table only; do not bounce")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    return parser.parse_args()


def main():
    args = parse_args()

    expected_macs = {m.lower() for m in args.expected_macs}

    device = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "secret": args.secret,
        "port": args.port,
    }

    try:
        log.info("Connecting to %s", args.device)
        conn = ConnectHandler(**device)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", args.device)
        sys.exit(1)

    try:
        if device["secret"]:
            conn.enable()

        pre_macs = get_mac_table(conn, args.interface)
        log.info("Pre-bounce MACs on %s: %s",
                 args.interface, ", ".join(sorted(pre_macs)) or "(none)")

        if args.dry_run:
            log.info("Dry-run mode — skipping bounce")
            conn.disconnect()
            return

        bounce_interface(conn, args.interface, args.hold_down)

        success, missing = wait_for_macs(
            conn, args.interface, expected_macs, args.verify_timeout
        )

        post_macs = get_mac_table(conn, args.interface)
        log.info("Post-bounce MACs on %s: %s",
                 args.interface, ", ".join(sorted(post_macs)) or "(none)")

        if expected_macs:
            if success:
                log.info("PASS — all %d expected MAC(s) relearned", len(expected_macs))
            else:
                log.error("FAIL — %d MAC(s) did not reappear: %s",
                          len(missing), ", ".join(sorted(missing)))
                sys.exit(2)
        else:
            log.info("Bounce complete (no MAC verification requested)")

    finally:
        conn.disconnect()


if __name__ == "__main__":
    main()
```