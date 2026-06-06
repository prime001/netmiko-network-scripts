err_disabled_recovery.py - Recover err-disabled interfaces via targeted port-bounce

Purpose:
    Detects interfaces in err-disabled state on Cisco IOS/IOS-XE devices and
    recovers them by performing a shutdown/no-shutdown cycle. Supports filtering
    by err-disable reason (bpduguard, psecure-violation, loopback, etc.) and
    includes pre/post verification that the interface actually leaves err-disabled.

Usage:
    python err_disabled_recovery.py -H 192.168.1.1 -u admin
    python err_disabled_recovery.py -H 192.168.1.1 -u admin --reason bpduguard
    python err_disabled_recovery.py -H 192.168.1.1 -u admin --dry-run
    python err_disabled_recovery.py -H 192.168.1.1 -u admin --interface GigabitEthernet0/1

Prerequisites:
    pip install netmiko
    IOS/IOS-XE device with SSH enabled and privilege level 15 access
    'errdisable recovery' may need to be disabled if auto-recovery is configured
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
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def parse_err_disabled(output: str) -> list[dict]:
    """Parse 'show interfaces status err-disabled' output into list of dicts."""
    results = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("port"):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            results.append({"interface": parts[0], "reason": parts[1]})
    return results


def recover_interface(conn, interface: str, delay: int) -> bool:
    """Cycle interface shutdown/no-shutdown. Returns True if commands succeeded."""
    try:
        log.info("  Shutting down %s", interface)
        conn.send_config_set([f"interface {interface}", "shutdown"])
        time.sleep(delay)
        log.info("  Bringing up %s", interface)
        conn.send_config_set([f"interface {interface}", "no shutdown"])
        return True
    except Exception as exc:
        log.error("  Config failed on %s: %s", interface, exc)
        return False


def verify_recovered(conn, interface: str, timeout: int) -> bool:
    """Poll interface status until err-disabled clears or timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = conn.send_command(f"show interfaces {interface} status")
        if "err-disabled" not in out.lower():
            return True
        remaining = int(deadline - time.time())
        log.info("  %s still err-disabled, waiting... (%ds remaining)", interface, remaining)
        time.sleep(5)
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Recover err-disabled interfaces on Cisco IOS/IOS-XE"
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--secret", help="Enable secret (defaults to password)")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=["cisco_ios", "cisco_xe", "cisco_nxos"],
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument(
        "--interface",
        help="Recover only this specific interface (e.g. GigabitEthernet0/1)",
    )
    parser.add_argument(
        "--reason",
        help="Filter by err-disable reason (e.g. bpduguard, psecure-violation)",
    )
    parser.add_argument(
        "--delay",
        type=int,
        default=3,
        help="Seconds between shutdown and no-shutdown (default: 3)",
    )
    parser.add_argument(
        "--verify-timeout",
        type=int,
        default=30,
        help="Seconds to wait for interface to recover (default: 30)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show err-disabled interfaces without making changes",
    )
    args = parser.parse_args()

    password = args.password or getpass(f"Password for {args.username}@{args.host}: ")
    secret = args.secret or password

    device_params = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": password,
        "secret": secret,
        "timeout": 30,
        "session_log": None,
    }

    try:
        log.info("Connecting to %s", args.host)
        conn = ConnectHandler(**device_params)
        conn.enable()
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        sys.exit(1)

    try:
        raw = conn.send_command("show interfaces status err-disabled")
        candidates = parse_err_disabled(raw)

        if args.interface:
            candidates = [
                c for c in candidates
                if args.interface.lower() in c["interface"].lower()
            ]
            if not candidates:
                log.info("%s is not currently err-disabled", args.interface)
                return

        if args.reason:
            candidates = [c for c in candidates if c["reason"] == args.reason]

        if not candidates:
            log.info("No err-disabled interfaces found matching the specified criteria")
            return

        log.info("Found %d err-disabled interface(s):", len(candidates))
        for entry in candidates:
            log.info("  %-35s  reason: %s", entry["interface"], entry["reason"])

        if args.dry_run:
            log.info("Dry-run mode — no changes applied")
            return

        recovered, failed = [], []
        for entry in candidates:
            intf = entry["interface"]
            log.info("Recovering %s (reason: %s)", intf, entry["reason"])
            if recover_interface(conn, intf, args.delay):
                if verify_recovered(conn, intf, args.verify_timeout):
                    log.info("  %s recovered successfully", intf)
                    recovered.append(intf)
                else:
                    log.warning("  %s bounced but did not clear err-disabled state", intf)
                    failed.append(intf)
            else:
                failed.append(intf)

        log.info(
            "Done — recovered: %d  failed: %d",
            len(recovered),
            len(failed),
        )
        if failed:
            log.warning("Interfaces still in err-disabled: %s", ", ".join(failed))
            sys.exit(1)

    finally:
        conn.disconnect()


if __name__ == "__main__":
    main()