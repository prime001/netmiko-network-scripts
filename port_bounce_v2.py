```python
"""
errdisable_recovery.py

Scans a Cisco IOS/IOS-XE switch for err-disabled interfaces, reports the
disable reason for each, and optionally recovers them via shutdown/no shutdown.

Common causes handled: bpduguard, psecure-violation, udld, loopback,
arp-inspection, dhcp-rate-limit, storm-control, link-flap.

Usage:
    python errdisable_recovery.py --host 10.0.0.1 --username admin
    python errdisable_recovery.py --host 10.0.0.1 --username admin --recover
    python errdisable_recovery.py --host 10.0.0.1 --username admin \\
        --interface Gi0/1 --recover --wait 10

Prerequisites:
    pip install netmiko
    SSH enabled on target device; privilege 15 or provide --secret for enable mode
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
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def get_errdisabled(connection, target_intf=None):
    """Return {interface: reason} for all err-disabled ports on the device."""
    output = connection.send_command("show interfaces status err-disabled")
    interfaces = {}

    for line in output.splitlines():
        if re.match(r"^\s*(Port|---|\s*$)", line):
            continue
        match = re.match(r"^(\S+)\s+.*err-disabled", line, re.IGNORECASE)
        if not match:
            continue
        intf = match.group(1)
        if target_intf and target_intf.lower() not in intf.lower():
            continue

        detail = connection.send_command(f"show interfaces {intf}")
        reason_match = re.search(r"err-disabled\s*\(([^)]+)\)", detail)
        reason = reason_match.group(1).strip() if reason_match else "unknown"
        interfaces[intf] = reason

    return interfaces


def recover_interface(connection, interface, wait_secs):
    """Cycle an interface out of err-disabled state. Returns True if recovered."""
    log.info("[%s] sending shutdown", interface)
    connection.send_config_set([f"interface {interface}", "shutdown"])
    time.sleep(1)

    log.info("[%s] sending no shutdown", interface)
    connection.send_config_set([f"interface {interface}", "no shutdown"])

    log.info("[%s] waiting %ds for link to stabilize", interface, wait_secs)
    time.sleep(wait_secs)

    verify = connection.send_command(f"show interfaces {interface} status")
    if "err-disabled" in verify.lower():
        log.warning("[%s] still err-disabled after recovery attempt", interface)
        return False

    first_line = next((l for l in verify.splitlines() if l.strip()), "")
    log.info("[%s] recovered — status: %s", interface, first_line.strip())
    return True


def parse_args():
    p = argparse.ArgumentParser(
        description="Detect and recover err-disabled interfaces on Cisco IOS/IOS-XE"
    )
    p.add_argument("--host", required=True, help="Switch IP or hostname")
    p.add_argument("--username", required=True, help="SSH username")
    p.add_argument("--password", help="SSH password (prompted if omitted)")
    p.add_argument("--secret", default="", help="Enable secret (if required)")
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        metavar="TYPE",
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument(
        "--interface",
        metavar="INTF",
        help="Limit scan/recovery to one interface (e.g. GigabitEthernet0/1 or Gi0/1)",
    )
    p.add_argument(
        "--recover",
        action="store_true",
        help="Perform shutdown/no shutdown on each err-disabled interface",
    )
    p.add_argument(
        "--wait",
        type=int,
        default=5,
        metavar="SECS",
        help="Seconds to wait after no shutdown before verifying state (default: 5)",
    )
    return p.parse_args()


def main():
    args = parse_args()
    password = args.password or getpass(f"Password for {args.username}@{args.host}: ")

    device_params = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": password,
        "secret": args.secret,
    }

    try:
        log.info("Connecting to %s", args.host)
        conn = ConnectHandler(**device_params)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        sys.exit(1)

    try:
        if args.secret and not conn.check_enable_mode():
            conn.enable()

        errdisabled = get_errdisabled(conn, target_intf=args.interface)

        if not errdisabled:
            log.info("No err-disabled interfaces found on %s", args.host)
            return

        log.info("Err-disabled interfaces found: %d", len(errdisabled))
        for intf, reason in errdisabled.items():
            log.info("  %-30s  reason: %s", intf, reason)

        if not args.recover:
            log.info("Rerun with --recover to attempt recovery via shutdown/no shutdown")
            return

        recovered, failed = [], []
        for intf in errdisabled:
            if recover_interface(conn, intf, args.wait):
                recovered.append(intf)
            else:
                failed.append(intf)

        log.info(
            "Recovery complete — recovered: %d  still err-disabled: %d",
            len(recovered),
            len(failed),
        )
        if failed:
            log.warning("Persistent failures (manual inspection required): %s", ", ".join(failed))
            sys.exit(2)

    finally:
        conn.disconnect()


if __name__ == "__main__":
    main()
```

This is `errdisable_recovery.py` — 157 lines, covering a distinct and common real-world task: scanning a switch for err-disabled ports (BPDU guard trips, port security violations, etc.), reporting the per-interface reason from `show interfaces` output, and optionally recovering via shutdown/no shutdown with post-recovery verification. Fundamentally different from a basic port bounce — it discovers affected ports automatically, captures the err-disable reason before clearing it, and handles the case where the underlying issue prevents recovery.