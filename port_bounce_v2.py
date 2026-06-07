```python
"""
err_disable_recovery.py - Detect and recover err-disabled switchports via Netmiko.

Purpose:
    Scans a Cisco IOS/IOS-XE switch for interfaces in err-disabled state and
    optionally recovers them with shutdown / no shutdown. Useful after security
    violations, BPDU guard trips, or flapping uplinks.

Usage:
    python err_disable_recovery.py --host 10.0.0.1 -u admin -p secret
    python err_disable_recovery.py --host 10.0.0.1 -u admin -p secret --recover
    python err_disable_recovery.py --host 10.0.0.1 -u admin -p secret \
        --recover --interface GigabitEthernet0/1

Prerequisites:
    pip install netmiko
    SSH enabled: ip ssh version 2
    Privilege-15 account or enable secret via --enable-secret
"""

import argparse
import logging
import re
import sys
import time

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

_ERR_DISABLED = re.compile(r"^(\S+)\s+\S+\s+err-disabled", re.IGNORECASE | re.MULTILINE)


def find_err_disabled(conn):
    """Return list of interface names in err-disabled state."""
    output = conn.send_command("show interfaces status err-disabled")
    if "Invalid" in output or output.lstrip().startswith("%"):
        output = conn.send_command("show interfaces status | include err-disabled")
    return _ERR_DISABLED.findall(output)


def get_cause(conn, interface):
    """Return the err-disable cause string for an interface, or 'unknown'."""
    output = conn.send_command("show errdisable recovery")
    for line in output.splitlines():
        if interface.lower() in line.lower():
            parts = line.split()
            if len(parts) >= 3:
                return parts[1]
    return "unknown"


def recover_interface(conn, interface, bounce_delay):
    """Issue shutdown then no shutdown with a configurable hold delay."""
    log.info("  Bouncing %s (hold=%ds)", interface, bounce_delay)
    conn.send_config_set([f"interface {interface}", "shutdown"])
    time.sleep(bounce_delay)
    conn.send_config_set([f"interface {interface}", "no shutdown"])


def verify_recovery(conn, interface, timeout):
    """Poll interface status until it leaves err-disabled or timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(3)
        output = conn.send_command(f"show interfaces {interface} status")
        if "err-disabled" not in output.lower():
            match = re.search(r"\b(connected|notconnect|disabled)\b", output, re.IGNORECASE)
            return True, (match.group(1) if match else "up")
    return False, "err-disabled"


def parse_args():
    p = argparse.ArgumentParser(
        description="Detect and recover err-disabled switchports on Cisco IOS/IOS-XE."
    )
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)
    p.add_argument("--enable-secret", default="", metavar="SECRET")
    p.add_argument("--device-type", default="cisco_ios", metavar="TYPE",
                   help="Netmiko device type (default: cisco_ios)")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--recover", action="store_true",
                   help="Attempt shutdown/no-shutdown recovery on detected interfaces")
    p.add_argument("--interface", metavar="INTF",
                   help="Scope to a single interface instead of scanning all")
    p.add_argument("--bounce-delay", type=int, default=3, metavar="SECS",
                   help="Seconds to hold shutdown before no shutdown (default: 3)")
    p.add_argument("--verify-timeout", type=int, default=15, metavar="SECS",
                   help="Seconds to wait for interface to recover (default: 15)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args()


def main():
    args = parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "port": args.port,
        "username": args.username,
        "password": args.password,
        "secret": args.enable_secret,
        "conn_timeout": 10,
    }

    log.info("Connecting to %s (%s)", args.host, args.device_type)
    try:
        with ConnectHandler(**device) as conn:
            if args.enable_secret:
                conn.enable()

            if args.interface:
                interfaces = [args.interface]
            else:
                interfaces = find_err_disabled(conn)
                if not interfaces:
                    log.info("No err-disabled interfaces found on %s", args.host)
                    return 0
                log.info("Found %d err-disabled interface(s): %s",
                         len(interfaces), ", ".join(interfaces))

            exit_code = 0
            for intf in interfaces:
                cause = get_cause(conn, intf)
                log.info("  %s  cause=%s", intf, cause)

                if not args.recover:
                    continue

                recover_interface(conn, intf, args.bounce_delay)
                recovered, status = verify_recovery(conn, intf, args.verify_timeout)
                if recovered:
                    log.info("  %s recovered (status: %s)", intf, status)
                else:
                    log.warning("  %s still err-disabled after recovery attempt", intf)
                    exit_code = 1

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s:%d", args.host, args.port)
        return 1
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        return 1

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
```