```python
"""
Port Bounce with Pre/Post State Validation
==========================================
Bounces one or more switch interfaces and verifies recovery by comparing
pre/post MAC table entries, error counters, and operational state.

Use case: Clearing stuck MACs, resetting PoE devices, forcing LACP
renegotiation — anywhere a simple shutdown/no-shutdown isn't enough
and you need evidence the port actually recovered.

Prerequisites:
    pip install netmiko

Usage:
    python 031_port_bounce.py -H 192.168.1.1 -u admin -p secret \
        -i GigabitEthernet0/1 GigabitEthernet0/2 \
        --device-type cisco_ios --wait 10 --timeout 30

    # Bounce multiple ports from a file (one interface per line)
    python 031_port_bounce.py -H 192.168.1.1 -u admin -p secret \
        --interface-file ports.txt --wait 5

Supported device types: cisco_ios, cisco_nxos, cisco_xe, cisco_xr
"""

import argparse
import logging
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class PortState:
    name: str
    status: str = ""
    err_input: int = 0
    err_output: int = 0
    mac_count: int = 0
    raw_counters: str = ""
    raw_mac: str = ""
    error: str = ""
    recovered: Optional[bool] = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bounce switch ports with pre/post state validation"
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=["cisco_ios", "cisco_nxos", "cisco_xe", "cisco_xr"],
    )
    parser.add_argument(
        "-i", "--interfaces", nargs="+", metavar="IFACE", help="Interface(s) to bounce"
    )
    parser.add_argument(
        "--interface-file",
        metavar="FILE",
        help="File with one interface name per line",
    )
    parser.add_argument(
        "--wait",
        type=int,
        default=8,
        help="Seconds to wait between shutdown and no shutdown (default: 8)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Seconds to wait for port to return UP after bounce (default: 30)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Collect pre-state and print commands without executing",
    )
    return parser.parse_args()


def load_interfaces(args: argparse.Namespace) -> list[str]:
    ifaces: list[str] = []
    if args.interfaces:
        ifaces.extend(args.interfaces)
    if args.interface_file:
        try:
            with open(args.interface_file) as fh:
                ifaces.extend(
                    line.strip() for line in fh if line.strip() and not line.startswith("#")
                )
        except OSError as exc:
            log.error("Cannot read interface file: %s", exc)
            sys.exit(1)
    if not ifaces:
        log.error("No interfaces specified. Use -i or --interface-file.")
        sys.exit(1)
    return ifaces


def capture_state(conn, iface: str) -> PortState:
    state = PortState(name=iface)
    try:
        status_out = conn.send_command(
            f"show interfaces {iface} status", use_textfsm=False
        )
        state.status = "connected" if "connected" in status_out.lower() else "notconnect"

        counters_out = conn.send_command(f"show interfaces {iface} counters errors")
        state.raw_counters = counters_out
        for line in counters_out.splitlines():
            parts = line.split()
            if "input" in line.lower() and len(parts) >= 2:
                try:
                    state.err_input = int(parts[-1].replace(",", ""))
                except ValueError:
                    pass
            if "output" in line.lower() and len(parts) >= 2:
                try:
                    state.err_output = int(parts[-1].replace(",", ""))
                except ValueError:
                    pass

        mac_out = conn.send_command(f"show mac address-table interface {iface}")
        state.raw_mac = mac_out
        state.mac_count = sum(
            1 for line in mac_out.splitlines()
            if line.strip() and not line.startswith("Mac") and not line.startswith("-") and not line.startswith("Vlan")
        )
    except Exception as exc:
        state.error = str(exc)
        log.warning("[%s] State capture error: %s", iface, exc)
    return state


def bounce_port(conn, iface: str, wait: int, dry_run: bool) -> None:
    commands = [
        f"interface {iface}",
        "shutdown",
    ]
    log.info("[%s] Sending shutdown...", iface)
    if not dry_run:
        conn.send_config_set(commands)
        time.sleep(wait)
    else:
        log.info("[%s] DRY-RUN: would sleep %ds then send no shutdown", iface, wait)
        return

    commands_up = [f"interface {iface}", "no shutdown"]
    log.info("[%s] Sending no shutdown...", iface)
    conn.send_config_set(commands_up)


def wait_for_recovery(conn, iface: str, timeout: int) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = conn.send_command(f"show interfaces {iface} status")
        if "connected" in out.lower():
            return True
        time.sleep(2)
    return False


def print_summary(pre: PortState, post: PortState) -> None:
    delta_in = post.err_input - pre.err_input
    delta_out = post.err_output - pre.err_output
    mac_diff = post.mac_count - pre.mac_count

    status_icon = "OK" if post.recovered else "FAIL"
    log.info(
        "[%s] %s | status=%s | new_errs_in=%d new_errs_out=%d | "
        "mac_delta=%+d (%d->%d)",
        post.name, status_icon, post.status,
        delta_in, delta_out,
        mac_diff, pre.mac_count, post.mac_count,
    )
    if delta_in > 0 or delta_out > 0:
        log.warning("[%s] New errors detected after bounce — investigate.", post.name)


def main() -> int:
    args = parse_args()
    interfaces = load_interfaces(args)

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "timeout": 20,
    }

    try:
        log.info("Connecting to %s (%s)...", args.host, args.device_type)
        conn = ConnectHandler(**device)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        return 1

    pre_states: list[PortState] = []
    post_states: list[PortState] = []
    overall_ok = True

    try:
        for iface in interfaces:
            log.info("[%s] Capturing pre-bounce state...", iface)
            pre = capture_state(conn, iface)
            pre_states.append(pre)

        for pre in pre_states:
            bounce_port(conn, pre.name, args.wait, args.dry_run)

        if not args.dry_run:
            for pre in pre_states:
                log.info("[%s] Waiting up to %ds for recovery...", pre.name, args.timeout)
                recovered = wait_for_recovery(conn, pre.name, args.timeout)
                if not recovered:
                    log.error("[%s] Port did not return to connected state.", pre.name)
                    overall_ok = False

                post = capture_state(conn, pre.name)
                post.recovered = recovered
                post_states.append(post)
                print_summary(pre, post)
        else:
            log.info("Dry-run complete. No changes made.")
    finally:
        conn.disconnect()

    return 0 if overall_ok else 2


if __name__ == "__main__":
    sys.exit(main())
```