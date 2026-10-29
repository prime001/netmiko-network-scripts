```python
"""
interface_errors.py — Interface Error Counter Monitor

Purpose:
    Audits all interfaces on a Cisco device for error counters (CRC errors,
    input errors, output drops, giants, runts). Reports interfaces exceeding
    configurable thresholds, useful for spotting bad cables, duplex mismatches,
    and congested uplinks before they cause outages.

Usage:
    python interface_errors.py -d 192.168.1.1 -u admin
    python interface_errors.py -d 192.168.1.1 -u admin -p secret --device-type cisco_nxos
    python interface_errors.py -d 192.168.1.1 -u admin --crc-threshold 5 --drop-threshold 100
    python interface_errors.py -d 192.168.1.1 -u admin --all

Prerequisites:
    pip install netmiko
    Tested with: cisco_ios, cisco_xe, cisco_nxos
"""

import argparse
import getpass
import logging
import re
import sys

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

IFACE_HEADER = re.compile(r"^(\S+) is (up|down|administratively down)", re.MULTILINE)

ERROR_PATTERNS = {
    "crc": re.compile(r"(\d+) CRC"),
    "input_errors": re.compile(r"(\d+) input errors"),
    "output_drops": re.compile(r"(\d+) output drops"),
    "giants": re.compile(r"(\d+) giants"),
    "runts": re.compile(r"(\d+) runts"),
    "resets": re.compile(r"(\d+) interface resets"),
}


def parse_interface_errors(output):
    """Return a list of per-interface error counter dicts."""
    results = []
    # split() with a capturing group: [pre, name, state, body, name, state, body, ...]
    blocks = IFACE_HEADER.split(output)
    i = 1
    while i + 2 <= len(blocks) - 1:
        name, state, body = blocks[i], blocks[i + 1], blocks[i + 2]
        counters = {"interface": name, "state": state}
        for key, pattern in ERROR_PATTERNS.items():
            m = pattern.search(body)
            counters[key] = int(m.group(1)) if m else 0
        results.append(counters)
        i += 3
    return results


def exceeds_threshold(iface, args):
    return (
        iface["crc"] >= args.crc_threshold
        or iface["input_errors"] >= args.input_threshold
        or iface["output_drops"] >= args.drop_threshold
    )


def print_report(all_ifaces, flagged, args):
    print(f"\n{'=' * 68}")
    print(f"  Interface Error Report  —  {args.device}")
    print(f"{'=' * 68}")
    print(f"  Interfaces checked : {len(all_ifaces)}")
    print(
        f"  Thresholds         : CRC>={args.crc_threshold}  "
        f"InputErr>={args.input_threshold}  Drops>={args.drop_threshold}"
    )
    print(f"  Interfaces flagged : {len(flagged)}")
    print(f"{'=' * 68}\n")

    targets = all_ifaces if args.all else flagged
    if not targets:
        print("  No interfaces exceeded thresholds.")
        return

    hdr = (
        f"{'Interface':<28} {'State':<10} "
        f"{'CRC':>7} {'InErr':>7} {'Drops':>7} {'Giants':>7} {'Runts':>7}"
    )
    print(hdr)
    print("-" * len(hdr))

    flagged_set = {id(i) for i in flagged}
    for iface in targets:
        marker = " ***" if id(iface) in flagged_set else ""
        print(
            f"{iface['interface']:<28} {iface['state']:<10} "
            f"{iface['crc']:>7} {iface['input_errors']:>7} "
            f"{iface['output_drops']:>7} {iface['giants']:>7} "
            f"{iface['runts']:>7}{marker}"
        )

    if flagged and not args.all:
        print("\n  *** Exceeds at least one threshold")


def build_parser():
    p = argparse.ArgumentParser(
        description="Audit interface error counters on a network device."
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--crc-threshold", type=int, default=0, dest="crc_threshold",
        help="Flag interfaces with CRC errors >= N (default: 0)",
    )
    p.add_argument(
        "--input-threshold", type=int, default=0, dest="input_threshold",
        help="Flag interfaces with input errors >= N (default: 0)",
    )
    p.add_argument(
        "--drop-threshold", type=int, default=0, dest="drop_threshold",
        help="Flag interfaces with output drops >= N (default: 0)",
    )
    p.add_argument(
        "--all", action="store_true",
        help="Show all interfaces, not just those exceeding thresholds",
    )
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.password is None:
        args.password = getpass.getpass(f"Password for {args.username}@{args.device}: ")

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }

    try:
        logger.info("Connecting to %s", args.device)
        with ConnectHandler(**device_params) as conn:
            logger.info("Fetching interface counters...")
            raw = conn.send_command("show interfaces", read_timeout=90)

        all_ifaces = parse_interface_errors(raw)
        if not all_ifaces:
            logger.error("No interfaces parsed — check device type or output format")
            sys.exit(1)

        logger.info("Parsed %d interfaces", len(all_ifaces))
        flagged = [i for i in all_ifaces if exceeds_threshold(i, args)]
        print_report(all_ifaces, flagged, args)

        if flagged:
            logger.warning("%d interface(s) exceeded error thresholds", len(flagged))
            sys.exit(2)

    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        logger.error("Connection timed out to %s:%s", args.device, args.port)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Aborted by user")
        sys.exit(130)
    except Exception as exc:
        logger.error("Unexpected error: %s", exc)
        sys.exit(1)
```