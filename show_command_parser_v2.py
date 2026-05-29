interface_baseline.py - Interface error counter baseline capture and drift detection.

Purpose:
    Captures interface error/drop counters as a point-in-time snapshot, then
    compares subsequent runs against that baseline to detect counter drift.
    Useful for pre/post validation during maintenance windows: run --save before
    a change and --compare after to confirm no new errors were introduced.

Usage:
    # Capture a pre-change baseline:
    python interface_baseline.py --host 10.0.0.1 --user admin --password secret --save baseline.json

    # Compare post-change counters against baseline:
    python interface_baseline.py --host 10.0.0.1 --user admin --password secret --compare baseline.json

    # Display current error counters only (no file I/O):
    python interface_baseline.py --host 10.0.0.1 --user admin --password secret

    # Non-zero exit code when drift is detected (useful in CI/scripts):
    python interface_baseline.py ... --compare baseline.json; echo $?

Prerequisites:
    pip install netmiko
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


VENDOR_COMMANDS = {
    "cisco_ios": "show interfaces",
    "cisco_nxos": "show interface",
    "cisco_xr": "show interfaces",
    "arista_eos": "show interfaces",
    "cisco_ios_xe": "show interfaces",
}

ERROR_FIELDS = [
    "input_errors",
    "output_errors",
    "crc",
    "frame",
    "overrun",
    "ignored",
    "input_drops",
    "output_drops",
    "collisions",
]

_PATTERNS = [
    (re.compile(r"(\d+)\s+input errors"), "input_errors"),
    (re.compile(r"(\d+)\s+output errors"), "output_errors"),
    (re.compile(r"(\d+)\s+CRC"), "crc"),
    (re.compile(r"(\d+)\s+frame"), "frame"),
    (re.compile(r"(\d+)\s+overrun"), "overrun"),
    (re.compile(r"(\d+)\s+ignored"), "ignored"),
    (re.compile(r"(\d+)\s+input drops"), "input_drops"),
    (re.compile(r"(\d+)\s+output drops"), "output_drops"),
    (re.compile(r"(\d+)\s+collisions"), "collisions"),
]

_IFACE_RE = re.compile(r"^(\S+)\s+is\s+(?:up|down|administratively down)", re.MULTILINE)


def parse_interfaces(output: str) -> dict:
    interfaces = {}
    current = None

    for line in output.splitlines():
        m = _IFACE_RE.match(line)
        if m:
            current = m.group(1)
            interfaces[current] = {f: 0 for f in ERROR_FIELDS}
            continue

        if not current:
            continue

        for pattern, field in _PATTERNS:
            m = pattern.search(line)
            if m:
                interfaces[current][field] = int(m.group(1))

    return interfaces


def collect_counters(conn, device_type: str) -> dict:
    command = VENDOR_COMMANDS.get(device_type, "show interfaces")
    log.info("Sending: %s", command)
    output = conn.send_command(command, read_timeout=60)
    counters = parse_interfaces(output)
    log.info("Parsed %d interfaces", len(counters))
    return counters


def save_baseline(counters: dict, path: str, host: str) -> None:
    payload = {
        "host": host,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "counters": counters,
    }
    Path(path).write_text(json.dumps(payload, indent=2))
    log.info("Baseline written to %s", path)


def compare_baseline(current: dict, path: str) -> list:
    raw = json.loads(Path(path).read_text())
    baseline = raw["counters"]
    log.info("Baseline timestamp: %s  host: %s", raw.get("timestamp"), raw.get("host"))

    drifts = []
    for iface, cur_vals in current.items():
        base_vals = baseline.get(iface, {})
        deltas = {
            f: cur_vals.get(f, 0) - base_vals.get(f, 0)
            for f in ERROR_FIELDS
            if cur_vals.get(f, 0) - base_vals.get(f, 0) > 0
        }
        if deltas:
            drifts.append({"interface": iface, "deltas": deltas})

    return drifts


def print_current(counters: dict) -> None:
    active = {k: v for k, v in counters.items() if any(v.values())}
    if not active:
        print("All interfaces: no error counters detected.")
        return
    print(f"\n{'Interface':<32} {'Counter':<22} {'Value':>12}")
    print("-" * 68)
    for iface in sorted(active):
        for field, count in sorted(active[iface].items()):
            if count:
                print(f"{iface:<32} {field:<22} {count:>12,}")


def print_drifts(drifts: list) -> None:
    if not drifts:
        print("PASS: No counter drift detected vs. baseline.")
        return
    print(f"\n{'Interface':<32} {'Counter':<22} {'Delta':>12}")
    print("-" * 68)
    for entry in sorted(drifts, key=lambda x: x["interface"]):
        for field, delta in sorted(entry["deltas"].items()):
            print(f"{entry['interface']:<32} {field:<22} +{delta:>11,}")
    print(f"\nFAIL: {len(drifts)} interface(s) show counter drift since baseline.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Capture interface error baseline and detect counter drift."
    )
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("--user", required=True, help="SSH username")
    p.add_argument("--password", required=True, help="SSH password")
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(VENDOR_COMMANDS.keys()),
        metavar="TYPE",
        help=f"Netmiko device type. Choices: {', '.join(VENDOR_COMMANDS)} (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--save", metavar="FILE", help="Save current counters as a baseline JSON file")
    p.add_argument(
        "--compare",
        metavar="FILE",
        help="Compare current counters against a saved baseline; exits 1 on drift",
    )
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.user,
        "password": args.password,
        "port": args.port,
    }

    try:
        log.info("Connecting to %s:%d", args.host, args.port)
        with ConnectHandler(**device) as conn:
            counters = collect_counters(conn, args.device_type)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.user, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        sys.exit(1)
    except Exception as exc:
        log.error("Connection error: %s", exc)
        sys.exit(1)

    if args.save:
        save_baseline(counters, args.save, args.host)
        print_current(counters)
    elif args.compare:
        drifts = compare_baseline(counters, args.compare)
        print_drifts(drifts)
        sys.exit(1 if drifts else 0)
    else:
        print_current(counters)