```python
"""
interface_error_monitor.py — Netmiko Interface Error Rate Monitor

Purpose:
    Polls a device's interface error counters twice, separated by a configurable
    interval, then reports per-interface error rates (errors/sec). Flags any
    interface whose input errors, output errors, or CRC count exceeds a threshold.
    Useful for diagnosing CRC storms, duplex mismatches, or flapping links without
    requiring SNMP infrastructure.

Usage:
    python interface_error_monitor.py --host 192.168.1.1 --username admin \
        --device-type cisco_ios --interval 60 --threshold 1.0

Prerequisites:
    pip install netmiko
    Supported platforms: Cisco IOS/IOS-XE/NX-OS, Arista EOS, Juniper JunOS
"""

import argparse
import getpass
import logging
import re
import sys
import time

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

SHOW_COMMANDS = {
    "cisco_ios": "show interfaces",
    "cisco_xe": "show interfaces",
    "cisco_nxos": "show interface",
    "arista_eos": "show interfaces",
    "juniper_junos": "show interfaces detail",
}

_PATTERNS = {
    "interface": re.compile(r"^(\S+) is (?:up|down|administratively down)", re.MULTILINE),
    "input_errors": re.compile(r"(\d+) input errors", re.IGNORECASE),
    "output_errors": re.compile(r"(\d+) output errors", re.IGNORECASE),
    "crc": re.compile(r"(\d+) CRC", re.IGNORECASE),
}


def _extract(pattern: re.Pattern, text: str) -> int:
    m = pattern.search(text)
    return int(m.group(1)) if m else 0


def parse_counters(raw: str) -> dict:
    """Parse show interfaces output into {iface: {metric: count}} structure."""
    counters = {}
    blocks = re.split(r"(?=^\S)", raw, flags=re.MULTILINE)
    for block in blocks:
        m = _PATTERNS["interface"].search(block)
        if not m:
            continue
        iface = m.group(1)
        counters[iface] = {
            "input_errors": _extract(_PATTERNS["input_errors"], block),
            "output_errors": _extract(_PATTERNS["output_errors"], block),
            "crc": _extract(_PATTERNS["crc"], block),
        }
    return counters


def compute_rates(before: dict, after: dict, elapsed: float) -> list[tuple]:
    """Return (iface, metric, rate, delta) for every counter that increased."""
    rows = []
    for iface, post in after.items():
        pre = before.get(iface, {})
        for metric in ("input_errors", "output_errors", "crc"):
            delta = post.get(metric, 0) - pre.get(metric, 0)
            if delta > 0:
                rows.append((iface, metric, delta / elapsed, delta))
    return rows


def collect(conn, device_type: str) -> dict:
    cmd = SHOW_COMMANDS.get(device_type, "show interfaces")
    log.debug("Sending: %s", cmd)
    return parse_counters(conn.send_command(cmd))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Monitor per-interface error rates on a network device via Netmiko."
    )
    p.add_argument("--host", required=True, help="Device hostname or IP address")
    p.add_argument("--username", required=True, help="SSH username")
    p.add_argument("--password", help="SSH password (prompted if omitted)")
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(SHOW_COMMANDS),
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=30, help="SSH timeout in seconds")
    p.add_argument("--enable-secret", help="Enable secret for privilege escalation")
    p.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Seconds between the two counter polls (default: 60)",
    )
    p.add_argument(
        "--threshold",
        type=float,
        default=1.0,
        help="Flag interfaces with error rate >= this value (errors/sec, default: 1.0)",
    )
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


def main() -> None:
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    if not args.password:
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    device_params = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "timeout": args.timeout,
    }
    if args.enable_secret:
        device_params["secret"] = args.enable_secret

    log.info("Connecting to %s (%s)", args.host, args.device_type)
    try:
        conn = ConnectHandler(**device_params)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        sys.exit(1)

    try:
        log.info("Baseline sample...")
        baseline = collect(conn, args.device_type)
        log.info("Captured %d interfaces. Waiting %ds...", len(baseline), args.interval)
        t0 = time.monotonic()
        time.sleep(args.interval)
        elapsed = time.monotonic() - t0
        log.info("Second sample...")
        sample = collect(conn, args.device_type)
    finally:
        conn.disconnect()

    rates = compute_rates(baseline, sample, elapsed)

    if not rates:
        log.info("No errors detected on any interface over the %ds window.", args.interval)
        return

    flagged = [r for r in rates if r[2] >= args.threshold]
    log.info(
        "%d counter(s) with errors; %d at/above threshold (%.2f/sec)",
        len(rates),
        len(flagged),
        args.threshold,
    )

    header = f"\n{'Interface':<32} {'Metric':<16} {'Errors/sec':>12} {'Delta':>8}"
    print(header)
    print("-" * 70)
    for iface, metric, rate, delta in sorted(rates, key=lambda r: -r[2]):
        flag = "  <-- ALERT" if rate >= args.threshold else ""
        print(f"{iface:<32} {metric:<16} {rate:>12.3f} {delta:>8}{flag}")

    if flagged:
        sys.exit(2)


if __name__ == "__main__":
    main()
```