```python
"""
003_firmware_check.py — Firmware compliance checker for network devices.

Connects to one or more devices via Netmiko, retrieves the running OS version,
and compares it against a required minimum version. Outputs a per-device
compliance report to stdout and optionally to a JSON file.

Usage:
    # Single device
    python 003_firmware_check.py --host 192.168.1.1 --device-type cisco_ios \
        --username admin --password secret --required-version 15.9(3)M2

    # Inventory file (CSV: host,device_type,required_version)
    python 003_firmware_check.py --inventory devices.csv \
        --username admin --password secret --output results.json

Prerequisites:
    pip install netmiko
    Network reachability + SSH access to target devices.
    Supported device types: cisco_ios, cisco_nxos, cisco_xr, arista_eos.
"""

import argparse
import csv
import json
import logging
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

VERSION_COMMANDS = {
    "cisco_ios": "show version",
    "cisco_nxos": "show version",
    "cisco_xr": "show version",
    "arista_eos": "show version",
}

VERSION_PATTERNS = {
    "cisco_ios": r"Cisco IOS Software.*Version\s+(\S+),",
    "cisco_nxos": r"NXOS:\s+version\s+(\S+)",
    "cisco_xr": r"Cisco IOS XR Software.*Version\s+(\S+)",
    "arista_eos": r"EOS version:\s+(\S+)",
}


@dataclass
class DeviceResult:
    host: str
    device_type: str
    required_version: str
    running_version: str
    compliant: bool
    error: Optional[str]
    checked_at: str


def get_running_version(host: str, device_type: str, username: str, password: str,
                         port: int = 22, timeout: int = 30) -> str:
    import re

    pattern = VERSION_PATTERNS.get(device_type)
    if not pattern:
        raise ValueError(f"Unsupported device type: {device_type}")

    connection_args = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "conn_timeout": timeout,
    }

    log.info("Connecting to %s (%s)", host, device_type)
    with ConnectHandler(**connection_args) as conn:
        output = conn.send_command(VERSION_COMMANDS[device_type])

    match = re.search(pattern, output, re.IGNORECASE)
    if not match:
        raise RuntimeError(f"Could not parse version from output on {host}")
    return match.group(1)


def check_device(host: str, device_type: str, required_version: str,
                 username: str, password: str, port: int = 22,
                 timeout: int = 30) -> DeviceResult:
    now = datetime.utcnow().isoformat() + "Z"
    try:
        running = get_running_version(host, device_type, username, password, port, timeout)
        compliant = running == required_version
        if compliant:
            log.info("%s: COMPLIANT (%s)", host, running)
        else:
            log.warning("%s: NON-COMPLIANT running=%s required=%s", host, running, required_version)
        return DeviceResult(host, device_type, required_version, running, compliant, None, now)
    except AuthenticationException:
        msg = "Authentication failed"
        log.error("%s: %s", host, msg)
        return DeviceResult(host, device_type, required_version, "", False, msg, now)
    except NetmikoTimeoutException:
        msg = "Connection timed out"
        log.error("%s: %s", host, msg)
        return DeviceResult(host, device_type, required_version, "", False, msg, now)
    except Exception as exc:
        log.error("%s: %s", host, exc)
        return DeviceResult(host, device_type, required_version, "", False, str(exc), now)


def load_inventory(path: str) -> list[dict]:
    devices = []
    with open(path, newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            devices.append(row)
    return devices


def print_report(results: list[DeviceResult]) -> None:
    print(f"\n{'HOST':<20} {'TYPE':<14} {'REQUIRED':<20} {'RUNNING':<20} STATUS")
    print("-" * 85)
    for r in results:
        status = "COMPLIANT" if r.compliant else ("ERROR" if r.error else "NON-COMPLIANT")
        print(f"{r.host:<20} {r.device_type:<14} {r.required_version:<20} {r.running_version:<20} {status}")
    compliant = sum(1 for r in results if r.compliant)
    print(f"\n{compliant}/{len(results)} devices compliant\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check firmware compliance on network devices.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="Single device IP or hostname")
    group.add_argument("--inventory", help="CSV inventory file (columns: host,device_type,required_version)")
    parser.add_argument("--device-type", choices=list(VERSION_COMMANDS), help="Device type (single-host mode)")
    parser.add_argument("--required-version", help="Required firmware version (single-host mode)")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=30, help="Connection timeout seconds (default: 30)")
    parser.add_argument("--output", help="Write JSON results to this file")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.host:
        if not args.device_type or not args.required_version:
            sys.exit("--device-type and --required-version are required with --host")
        devices = [{"host": args.host, "device_type": args.device_type,
                    "required_version": args.required_version}]
    else:
        devices = load_inventory(args.inventory)

    results = [
        check_device(
            host=d["host"],
            device_type=d["device_type"],
            required_version=d["required_version"],
            username=args.username,
            password=args.password,
            port=args.port,
            timeout=args.timeout,
        )
        for d in devices
    ]

    print_report(results)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump([asdict(r) for r in results], fh, indent=2)
        log.info("Results written to %s", args.output)

    non_compliant = [r for r in results if not r.compliant]
    sys.exit(1 if non_compliant else 0)
```