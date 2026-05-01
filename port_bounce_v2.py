The repo listed in the prompt is a different GitHub portfolio repo. I'll write the script directly:

```python
#!/usr/bin/env python3
"""
011_errdisable_recovery.py — Err-Disabled Port Detection and Recovery

Purpose:
    Connects to a Cisco IOS/IOS-XE switch, identifies all interfaces in
    err-disabled state, logs the cause per port, and optionally recovers
    them by issuing shutdown / no shutdown with configurable dwell time.

Usage:
    python 011_errdisable_recovery.py -d 192.168.1.1 -u admin -p secret
    python 011_errdisable_recovery.py -d 192.168.1.1 -u admin --recover
    python 011_errdisable_recovery.py -d 192.168.1.1 -u admin --recover --port GigabitEthernet0/1
    python 011_errdisable_recovery.py -d 192.168.1.1 -u admin --recover --dwell 10

Prerequisites:
    pip install netmiko
    Read/write SSH access to the target device.
    'errdisable' detection requires IOS 12.2+ or IOS-XE 3.x+.
"""

import argparse
import getpass
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

ERRDISABLE_RE = re.compile(
    r"^(\S+)\s+err-disabled\s+.*?errdisable\s+(\S+)", re.MULTILINE
)
CAUSE_RE = re.compile(r"^(\S+)\s+\S+\s+\S+\s+([\w-]+)", re.MULTILINE)


@dataclass
class ErrDisabledPort:
    interface: str
    cause: str = "unknown"
    recovered: bool = False
    error: str = ""


def parse_errdisabled(show_if_output: str, show_cause_output: str) -> list[ErrDisabledPort]:
    ports: dict[str, ErrDisabledPort] = {}

    for match in ERRDISABLE_RE.finditer(show_if_output):
        iface = match.group(1)
        ports[iface] = ErrDisabledPort(interface=iface)

    for match in CAUSE_RE.finditer(show_cause_output):
        iface = match.group(1)
        cause = match.group(2)
        if iface in ports:
            ports[iface].cause = cause

    return list(ports.values())


def detect(conn) -> list[ErrDisabledPort]:
    log.info("Collecting interface status...")
    show_if = conn.send_command("show interfaces status err-disabled", read_timeout=30)

    if "Invalid input" in show_if or not show_if.strip():
        show_if = conn.send_command("show interface status", read_timeout=30)

    show_cause = conn.send_command("show errdisable recovery", read_timeout=30)

    ports = parse_errdisabled(show_if, show_cause)

    if not ports:
        # fallback: grep all interfaces for Err-Disabled in show int output
        show_all = conn.send_command("show interfaces | include (^[A-Z]|err-disabled)", read_timeout=60)
        current_iface = None
        for line in show_all.splitlines():
            iface_match = re.match(r"^([A-Z]\S+)\s+is", line)
            if iface_match:
                current_iface = iface_match.group(1)
            if "err-disabled" in line.lower() and current_iface:
                ports.append(ErrDisabledPort(interface=current_iface))
                current_iface = None

    return ports


def recover_port(conn, port: ErrDisabledPort, dwell: int) -> None:
    log.info("Recovering %s (cause: %s)...", port.interface, port.cause)
    try:
        conn.send_config_set([
            f"interface {port.interface}",
            "shutdown",
        ])
        time.sleep(dwell)
        conn.send_config_set([
            f"interface {port.interface}",
            "no shutdown",
        ])
        time.sleep(2)

        status = conn.send_command(
            f"show interface {port.interface} | include line protocol",
            read_timeout=15,
        )
        if "err-disabled" in status.lower():
            port.error = "still err-disabled after recovery attempt"
            log.warning("%s still err-disabled after recovery.", port.interface)
        else:
            port.recovered = True
            log.info("%s recovered successfully.", port.interface)

    except Exception as exc:
        port.error = str(exc)
        log.error("Failed to recover %s: %s", port.interface, exc)


def print_report(ports: list[ErrDisabledPort], attempted_recovery: bool) -> None:
    print("\n" + "=" * 60)
    print(f"{'INTERFACE':<30} {'CAUSE':<20} {'STATUS'}")
    print("-" * 60)
    for p in ports:
        if not attempted_recovery:
            status = "err-disabled"
        elif p.recovered:
            status = "RECOVERED"
        else:
            status = f"FAILED ({p.error})" if p.error else "unresolved"
        print(f"{p.interface:<30} {p.cause:<20} {status}")
    print("=" * 60)
    print(f"Total err-disabled: {len(ports)}")
    if attempted_recovery:
        recovered = sum(1 for p in ports if p.recovered)
        print(f"Recovered: {recovered} / {len(ports)}")
    print()


def build_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect and recover err-disabled switchports via Netmiko."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--device-type", default="cisco_ios", help="Netmiko device type (default: cisco_ios)")
    parser.add_argument("--port", help="Recover only this interface (e.g. GigabitEthernet0/1)")
    parser.add_argument("--recover", action="store_true", help="Attempt shutdown/no shutdown recovery")
    parser.add_argument("--dwell", type=int, default=5, help="Seconds between shutdown and no shutdown (default: 5)")
    parser.add_argument("--secret", help="Enable secret if required")
    return parser.parse_args()


def main() -> int:
    args = build_args()
    password = args.password or getpass.getpass(f"Password for {args.username}@{args.device}: ")

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": password,
        "secret": args.secret or "",
        "conn_timeout": 15,
    }

    log.info("Connecting to %s (%s)...", args.device, args.device_type)
    try:
        with ConnectHandler(**device_params) as conn:
            if args.secret:
                conn.enable()

            ports = detect(conn)

            if not ports:
                log.info("No err-disabled interfaces found on %s.", args.device)
                return 0

            log.info("Found %d err-disabled interface(s).", len(ports))

            if args.recover:
                targets = ports
                if args.port:
                    targets = [p for p in ports if args.port.lower() in p.interface.lower()]
                    if not targets:
                        log.error("Interface %s not found in err-disabled list.", args.port)
                        print_report(ports, attempted_recovery=False)
                        return 1

                for port in targets:
                    recover_port(conn, port, args.dwell)

                print_report(ports, attempted_recovery=True)
                failed = [p for p in targets if not p.recovered]
                return 1 if failed else 0
            else:
                print_report(ports, attempted_recovery=False)
                return 0

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s.", args.username, args.device)
        return 2
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s.", args.device)
        return 2
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
```