```python
"""
027_health_check.py - Interface Error and Utilization Health Check

Purpose:
    Connects to one or more Cisco IOS/IOS-XE devices and checks interface
    health by parsing error counters (input errors, CRC, output drops) and
    comparing utilization against configurable thresholds. Exits non-zero if
    any interface exceeds a threshold, making it CI/CD and monitoring friendly.

Usage:
    Single device:
        python 027_health_check.py -d 192.168.1.1 -u admin -p secret

    Multiple devices from file (one IP per line):
        python 027_health_check.py -f devices.txt -u admin -p secret

    Raise utilization threshold:
        python 027_health_check.py -d 192.168.1.1 -u admin --util-warn 80

Prerequisites:
    pip install netmiko
    Device must support: show interfaces, show interfaces summary
    SSH access with privilege level 1 or higher
"""

import argparse
import logging
import re
import sys
from dataclasses import dataclass, field
from getpass import getpass
from typing import List, Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)


@dataclass
class InterfaceHealth:
    name: str
    status: str
    input_errors: int = 0
    crc_errors: int = 0
    output_drops: int = 0
    input_rate_bps: int = 0
    output_rate_bps: int = 0
    bandwidth_kbps: int = 0
    warnings: List[str] = field(default_factory=list)

    @property
    def util_pct(self) -> Optional[float]:
        if self.bandwidth_kbps <= 0:
            return None
        peak = max(self.input_rate_bps, self.output_rate_bps)
        return round((peak / (self.bandwidth_kbps * 1000)) * 100, 1)


def parse_interfaces(raw: str, error_threshold: int, util_warn: int) -> List[InterfaceHealth]:
    interfaces: List[InterfaceHealth] = []
    blocks = re.split(r"\n(?=\S)", raw)

    for block in blocks:
        name_match = re.match(r"^(\S+) is (\S+)", block)
        if not name_match:
            continue

        iface = InterfaceHealth(
            name=name_match.group(1),
            status=name_match.group(2),
        )

        bw = re.search(r"BW (\d+) Kbit", block)
        if bw:
            iface.bandwidth_kbps = int(bw.group(1))

        in_rate = re.search(r"input rate (\d+) bits", block)
        out_rate = re.search(r"output rate (\d+) bits", block)
        if in_rate:
            iface.input_rate_bps = int(in_rate.group(1))
        if out_rate:
            iface.output_rate_bps = int(out_rate.group(1))

        in_err = re.search(r"(\d+) input errors", block)
        crc = re.search(r"(\d+) CRC", block)
        out_drop = re.search(r"(\d+) output drops", block)
        if in_err:
            iface.input_errors = int(in_err.group(1))
        if crc:
            iface.crc_errors = int(crc.group(1))
        if out_drop:
            iface.output_drops = int(out_drop.group(1))

        if iface.input_errors > error_threshold:
            iface.warnings.append(f"input errors {iface.input_errors} > {error_threshold}")
        if iface.crc_errors > error_threshold:
            iface.warnings.append(f"CRC errors {iface.crc_errors} > {error_threshold}")
        if iface.output_drops > error_threshold:
            iface.warnings.append(f"output drops {iface.output_drops} > {error_threshold}")

        util = iface.util_pct
        if util is not None and util >= util_warn:
            iface.warnings.append(f"utilization {util}% >= {util_warn}%")

        interfaces.append(iface)

    return interfaces


def check_device(host: str, username: str, password: str, device_type: str,
                 error_threshold: int, util_warn: int) -> int:
    device_params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "timeout": 30,
    }

    print(f"\n[{host}] Connecting...")
    try:
        with ConnectHandler(**device_params) as conn:
            raw = conn.send_command("show interfaces", read_timeout=60)
    except NetmikoAuthenticationException:
        log.error("[%s] Authentication failed", host)
        return 1
    except NetmikoTimeoutException:
        log.error("[%s] Connection timed out", host)
        return 1
    except Exception as exc:
        log.error("[%s] Unexpected error: %s", host, exc)
        return 1

    interfaces = parse_interfaces(raw, error_threshold, util_warn)
    issues = [i for i in interfaces if i.warnings]
    healthy = [i for i in interfaces if not i.warnings and i.status == "up"]

    print(f"[{host}] {len(interfaces)} interfaces checked — "
          f"{len(healthy)} healthy, {len(issues)} with warnings")

    for iface in issues:
        for warn in iface.warnings:
            print(f"  WARN  {iface.name}: {warn}")

    return 1 if issues else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check interface error counters and utilization on Cisco IOS devices"
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--device", help="Single device IP or hostname")
    target.add_argument("-f", "--file", help="File with one device IP per line")

    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", default=None,
                        help="Password (prompted if omitted)")
    parser.add_argument("--device-type", default="cisco_ios",
                        help="Netmiko device type (default: cisco_ios)")
    parser.add_argument("--error-threshold", type=int, default=0,
                        help="Max acceptable error/drop count (default: 0)")
    parser.add_argument("--util-warn", type=int, default=75,
                        help="Utilization %% warning threshold (default: 75)")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}: ")

    if args.device:
        hosts = [args.device]
    else:
        try:
            with open(args.file) as fh:
                hosts = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"ERROR: device file '{args.file}' not found", file=sys.stderr)
            return 2

    exit_code = 0
    for host in hosts:
        rc = check_device(host, args.username, password, args.device_type,
                          args.error_threshold, args.util_warn)
        if rc:
            exit_code = rc

    print(f"\nResult: {'FAIL' if exit_code else 'PASS'}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
```