```python
"""
interface_error_recovery.py - Detect and remediate interfaces with incrementing error counters.

Purpose:
    Connects to a Cisco IOS/IOS-XE device, inspects interface error counters
    (CRC, input errors, output errors, runts, giants), and performs a controlled
    shutdown/no-shutdown on interfaces whose error counts exceed a configurable
    threshold. Pre/post counter snapshots confirm whether the bounce resolved
    the condition.

Usage:
    python interface_error_recovery.py -d 192.168.1.1 -u admin -p secret
    python interface_error_recovery.py -d 192.168.1.1 -u admin -p secret \
        --interface GigabitEthernet0/1 --threshold 100 --dry-run

Prerequisites:
    pip install netmiko
    Device must allow SSH and have enable access if needed.
"""

import argparse
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

ERROR_PATTERN = re.compile(
    r"(\S+)\s+is\s+(?:up|down).*?\n"
    r".*?(\d+)\s+input errors.*?\n"
    r".*?(\d+)\s+CRC.*?\n"
    r".*?(\d+)\s+output errors",
    re.DOTALL,
)

COUNTER_RE = re.compile(
    r"(\d+) input errors.*?(\d+) CRC.*?(\d+) output errors.*?(\d+) runts.*?(\d+) giants",
    re.DOTALL,
)


@dataclass
class InterfaceCounters:
    name: str
    input_errors: int = 0
    crc: int = 0
    output_errors: int = 0
    runts: int = 0
    giants: int = 0

    def total_errors(self) -> int:
        return self.input_errors + self.crc + self.output_errors + self.runts + self.giants


def parse_counters(interface: str, output: str) -> Optional[InterfaceCounters]:
    m = COUNTER_RE.search(output)
    if not m:
        return None
    return InterfaceCounters(
        name=interface,
        input_errors=int(m.group(1)),
        crc=int(m.group(2)),
        output_errors=int(m.group(3)),
        runts=int(m.group(4)),
        giants=int(m.group(5)),
    )


def get_interface_list(conn) -> list[str]:
    output = conn.send_command("show interfaces | include ^[A-Za-z]")
    interfaces = []
    for line in output.splitlines():
        m = re.match(r"^(\S+)\s+is\s+(?:up|down)", line)
        if m:
            interfaces.append(m.group(1))
    return interfaces


def get_counters(conn, interface: str) -> Optional[InterfaceCounters]:
    output = conn.send_command(f"show interfaces {interface}")
    return parse_counters(interface, output)


def bounce_interface(conn, interface: str, wait: int = 5, dry_run: bool = False) -> bool:
    if dry_run:
        log.info("[DRY-RUN] Would bounce %s (shutdown + %ds + no shutdown)", interface, wait)
        return True
    log.info("Bouncing %s ...", interface)
    try:
        conn.send_config_set([f"interface {interface}", "shutdown"])
        time.sleep(wait)
        conn.send_config_set([f"interface {interface}", "no shutdown"])
        time.sleep(3)
        return True
    except Exception as exc:
        log.error("Failed to bounce %s: %s", interface, exc)
        return False


def check_interface_up(conn, interface: str) -> bool:
    output = conn.send_command(f"show interfaces {interface} | include line protocol")
    return "up" in output.lower()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Recover interfaces with high error counters")
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("--secret", default="", help="Enable secret (if needed)")
    p.add_argument("--device-type", default="cisco_ios", help="Netmiko device type")
    p.add_argument("--interface", help="Target a single interface (default: all)")
    p.add_argument(
        "--threshold",
        type=int,
        default=50,
        help="Total error count that triggers a bounce (default: 50)",
    )
    p.add_argument(
        "--wait",
        type=int,
        default=5,
        help="Seconds to hold interface down during bounce (default: 5)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Report errors and bounce candidates without making changes",
    )
    return p


def main() -> int:
    args = build_parser().parse_args()

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "secret": args.secret,
        "timeout": 30,
    }

    log.info("Connecting to %s ...", args.device)
    try:
        conn = ConnectHandler(**device_params)
        if args.secret:
            conn.enable()
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.device)
        return 1
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", args.device)
        return 1

    interfaces = [args.interface] if args.interface else get_interface_list(conn)
    log.info("Checking %d interface(s) against threshold=%d", len(interfaces), args.threshold)

    candidates = []
    for iface in interfaces:
        counters = get_counters(conn, iface)
        if counters is None:
            log.warning("Could not parse counters for %s", iface)
            continue
        total = counters.total_errors()
        if total >= args.threshold:
            log.warning(
                "%s: %d total errors (input=%d crc=%d output=%d runts=%d giants=%d)",
                iface, total, counters.input_errors, counters.crc,
                counters.output_errors, counters.runts, counters.giants,
            )
            candidates.append(counters)

    if not candidates:
        log.info("No interfaces exceeded threshold. Nothing to do.")
        conn.disconnect()
        return 0

    log.info("%d interface(s) queued for bounce", len(candidates))
    exit_code = 0

    for pre in candidates:
        bounced = bounce_interface(conn, pre.name, wait=args.wait, dry_run=args.dry_run)
        if not bounced:
            exit_code = 1
            continue

        if args.dry_run:
            continue

        if not check_interface_up(conn, pre.name):
            log.error("%s did not come back up after bounce", pre.name)
            exit_code = 1
            continue

        post = get_counters(conn, pre.name)
        if post is None:
            log.warning("Could not read post-bounce counters for %s", pre.name)
            continue

        delta = post.total_errors() - pre.total_errors()
        if delta == 0:
            log.info("%s: counters cleared — bounce resolved the condition", pre.name)
        else:
            log.warning(
                "%s: %d new errors accumulated post-bounce (may need further investigation)",
                pre.name, delta,
            )

    conn.disconnect()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
```