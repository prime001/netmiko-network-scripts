```python
"""
interface_error_monitor.py - Network interface error counter analyzer.

Purpose:
    Connects to a Cisco device and inspects interface error counters to identify
    degraded links. Reports interfaces exceeding configurable thresholds for input
    errors, CRC errors, output drops, and interface resets. Useful for diagnosing
    duplex mismatches, bad cables, or failing SFP modules before they cause outages.

Usage:
    python interface_error_monitor.py -d 192.168.1.1 -u admin
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret --threshold-errors 10
    python interface_error_monitor.py -d 192.168.1.1 -u admin --clear-counters

Prerequisites:
    pip install netmiko

Supported device types: cisco_ios, cisco_xe, cisco_nxos
"""

import argparse
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)


def parse_interface_counters(output: str) -> list:
    """Parse 'show interfaces' output into per-interface error counter dicts."""
    interfaces = []
    current = {}

    for line in output.splitlines():
        m = re.match(r'^(\S+)\s+is\s+(up|down|administratively down)', line)
        if m:
            if current:
                interfaces.append(current)
            current = {
                "name": m.group(1),
                "status": m.group(2),
                "input_errors": 0,
                "crc_errors": 0,
                "output_drops": 0,
                "resets": 0,
            }
            continue

        if not current:
            continue

        m = re.search(r'(\d+)\s+input errors.*?(\d+)\s+CRC', line)
        if m:
            current["input_errors"] = int(m.group(1))
            current["crc_errors"] = int(m.group(2))
            continue

        m = re.search(r'(\d+)\s+output drops', line)
        if m:
            current["output_drops"] = int(m.group(1))
            continue

        m = re.search(r'(\d+)\s+interface resets', line)
        if m:
            current["resets"] = int(m.group(1))

    if current:
        interfaces.append(current)

    return interfaces


def flag_interfaces(interfaces: list, threshold_errors: int, threshold_drops: int) -> list:
    """Return interfaces whose counters exceed the given thresholds."""
    flagged = []
    for iface in interfaces:
        reasons = []
        if iface["input_errors"] >= threshold_errors:
            reasons.append(f"input_errors={iface['input_errors']}")
        if iface["crc_errors"] >= threshold_errors:
            reasons.append(f"crc_errors={iface['crc_errors']}")
        if iface["output_drops"] >= threshold_drops:
            reasons.append(f"output_drops={iface['output_drops']}")
        if reasons:
            flagged.append({**iface, "reasons": reasons})
    return flagged


def print_report(flagged: list, total: int) -> None:
    print(f"\n{'=' * 64}")
    print(f"Interface Error Report — {len(flagged)} flagged of {total} total")
    print(f"{'=' * 64}")
    if not flagged:
        print("  All interfaces within thresholds.\n")
        return
    fmt = "  {:<32} {:<10} {:>8} {:>8} {:>10} {:>7}"
    print(fmt.format("Interface", "Status", "InErr", "CRC", "OutDrops", "Resets"))
    print("  " + "-" * 60)
    for iface in flagged:
        print(fmt.format(
            iface["name"][:31],
            iface["status"],
            iface["input_errors"],
            iface["crc_errors"],
            iface["output_drops"],
            iface["resets"],
        ))
        print(f"    ^ {', '.join(iface['reasons'])}")
    print()


def clear_interface_counters(conn, interfaces: list) -> None:
    """Send clear counters to each flagged interface, confirming the prompt."""
    for iface in interfaces:
        name = iface["name"]
        logger.info("Clearing counters on %s", name)
        conn.send_command(
            f"clear counters {name}",
            expect_string=r"\[confirm\]|#",
            strip_prompt=False,
            strip_command=False,
        )
        conn.send_command("\n", expect_string=r"#")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Report interface error counters on a Cisco device."
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=["cisco_ios", "cisco_xe", "cisco_nxos"],
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument(
        "--threshold-errors",
        type=int,
        default=1,
        metavar="N",
        help="Flag when input/CRC errors >= N (default: 1)",
    )
    p.add_argument(
        "--threshold-drops",
        type=int,
        default=50,
        metavar="N",
        help="Flag when output drops >= N (default: 50)",
    )
    p.add_argument(
        "--clear-counters",
        action="store_true",
        help="Offer to clear counters on flagged interfaces after reporting",
    )
    p.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return p


def main() -> int:
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}@{args.device}: ")

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": password,
    }

    try:
        logger.info("Connecting to %s", args.device)
        with ConnectHandler(**device_params) as conn:
            logger.info("Retrieving interface counters")
            output = conn.send_command("show interfaces", read_timeout=60)

        interfaces = parse_interface_counters(output)
        flagged = flag_interfaces(interfaces, args.threshold_errors, args.threshold_drops)
        print_report(flagged, len(interfaces))

        if args.clear_counters and flagged:
            confirm = input(
                f"Clear counters on {len(flagged)} flagged interface(s)? [y/N] "
            ).strip().lower()
            if confirm == "y":
                with ConnectHandler(**device_params) as conn:
                    clear_interface_counters(conn, flagged)
                print(f"Cleared counters on {len(flagged)} interface(s).")
            else:
                print("Counter clear skipped.")

    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.device)
        return 1
    except NetmikoTimeoutException:
        logger.error("Connection timed out to %s", args.device)
        return 1
    except KeyboardInterrupt:
        print("\nAborted.")
        return 130
    except Exception as exc:
        logger.error("Unexpected error: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
```