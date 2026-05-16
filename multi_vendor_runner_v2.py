```python
"""
interface_error_monitor.py - Monitor interface error counters on network devices.

Purpose:
    Connects to a network device via SSH and reports interface error counters
    (input errors, output drops, CRC errors, giants, runts). Supports one-shot
    reporting or continuous polling with delta tracking and threshold-based alerting.
    Useful for catching bad cables, duplex mismatches, and oversubscribed links.

Usage:
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret --poll 60
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret \\
        --interface GigabitEthernet0/1 --threshold 10

Prerequisites:
    pip install netmiko
    Supported: cisco_ios, cisco_xe, cisco_nxos, cisco_xr
"""

import argparse
import logging
import re
import sys
import time
from dataclasses import dataclass
from typing import Dict, Optional

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


@dataclass
class InterfaceCounters:
    name: str
    input_errors: int = 0
    output_drops: int = 0
    crc: int = 0
    giants: int = 0
    runts: int = 0

    def total(self) -> int:
        return self.input_errors + self.output_drops + self.crc + self.giants + self.runts

    def delta(self, prev: "InterfaceCounters") -> "InterfaceCounters":
        return InterfaceCounters(
            name=self.name,
            input_errors=self.input_errors - prev.input_errors,
            output_drops=self.output_drops - prev.output_drops,
            crc=self.crc - prev.crc,
            giants=self.giants - prev.giants,
            runts=self.runts - prev.runts,
        )


def parse_cisco_counters(output: str) -> Dict[str, InterfaceCounters]:
    counters: Dict[str, InterfaceCounters] = {}
    current: Optional[str] = None

    iface_re = re.compile(r"^(\S+) is (?:up|down|administratively down)")
    input_re = re.compile(
        r"(\d+) input errors,\s*(\d+) CRC,\s*\d+ frame,\s*\d+ overrun,\s*(\d+) ignored"
    )
    runts_giants_re = re.compile(r"(\d+) runts,\s*(\d+) giants")
    drops_re = re.compile(r"(\d+) output drops")

    for line in output.splitlines():
        m = iface_re.match(line)
        if m:
            current = m.group(1)
            counters[current] = InterfaceCounters(name=current)
            continue

        if current is None:
            continue

        m = input_re.search(line)
        if m:
            counters[current].input_errors = int(m.group(1))
            counters[current].crc = int(m.group(2))

        m = runts_giants_re.search(line)
        if m:
            counters[current].runts = int(m.group(1))
            counters[current].giants = int(m.group(2))

        m = drops_re.search(line)
        if m:
            counters[current].output_drops = int(m.group(1))

    return counters


def fetch_counters(
    conn, device_type: str, interface: Optional[str]
) -> Dict[str, InterfaceCounters]:
    cmd = "show interfaces" if not interface else f"show interfaces {interface}"
    output = conn.send_command(cmd)
    if device_type in ("cisco_ios", "cisco_xe", "cisco_nxos", "cisco_xr"):
        return parse_cisco_counters(output)
    log.error("Unsupported device type '%s'", device_type)
    return {}


def report(
    current: Dict[str, InterfaceCounters],
    prev: Optional[Dict[str, InterfaceCounters]],
    threshold: int,
) -> bool:
    alerted = False
    for name, c in sorted(current.items()):
        total = c.total()
        if total == 0 and (prev is None or name not in prev):
            continue

        d: Optional[InterfaceCounters] = None
        if prev and name in prev:
            d = c.delta(prev[name])

        incrementing = d is not None and d.total() > 0
        over_threshold = total >= threshold if threshold > 0 else total > 0

        if not over_threshold and not incrementing:
            continue

        delta_str = ""
        if d and d.total() > 0:
            delta_str = (
                f" [+in_err={d.input_errors} +drops={d.output_drops}"
                f" +crc={d.crc} +giants={d.giants} +runts={d.runts}]"
            )

        level = logging.WARNING if (over_threshold and threshold > 0) else logging.INFO
        log.log(
            level,
            "%-40s in_err=%-6d drops=%-6d crc=%-6d giants=%-4d runts=%-4d%s",
            name, c.input_errors, c.output_drops, c.crc, c.giants, c.runts, delta_str,
        )
        if over_threshold:
            alerted = True

    return alerted


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Monitor interface error counters on network devices via SSH."
    )
    p.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument(
        "-t", "--device-type",
        default="cisco_ios",
        choices=["cisco_ios", "cisco_xe", "cisco_nxos", "cisco_xr"],
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("-i", "--interface", help="Limit to a single interface name")
    p.add_argument(
        "--poll", type=int, metavar="SECONDS",
        help="Poll continuously at this interval; omit for a single snapshot",
    )
    p.add_argument(
        "--threshold", type=int, default=0,
        help="Cumulative error count that triggers WARNING (0 = flag any non-zero)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug output")
    return p


def main() -> None:
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    device_params = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }

    log.info("Connecting to %s (%s)", args.host, args.device_type)
    try:
        conn = ConnectHandler(**device_params)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s:%d", args.host, args.port)
        sys.exit(1)

    prev: Optional[Dict[str, InterfaceCounters]] = None
    alerted = False
    try:
        while True:
            counters = fetch_counters(conn, args.device_type, args.interface)
            if not counters:
                log.warning("No counters parsed — check device type or interface name.")
            else:
                alerted = report(counters, prev, args.threshold)
                prev = counters

            if not args.poll:
                break
            log.info("Next poll in %d seconds — Ctrl+C to stop.", args.poll)
            time.sleep(args.poll)
    except KeyboardInterrupt:
        log.info("Stopped.")
    finally:
        conn.disconnect()

    sys.exit(1 if alerted else 0)


if __name__ == "__main__":
    main()
```