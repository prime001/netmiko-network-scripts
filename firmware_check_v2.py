```python
"""
033_firmware_check.py — Multi-device firmware compliance checker

Connects to one or more network devices, retrieves the running firmware version,
and compares it against a minimum required version per platform. Produces a
compliance report with PASS/FAIL status and optional CSV export.

Usage:
    Single device:
        python 033_firmware_check.py -H 10.0.0.1 -u admin -p secret \
            --device-type cisco_ios --min-version 15.2.7

    Inventory file (CSV: host,device_type,username,password,min_version):
        python 033_firmware_check.py --inventory devices.csv --output report.csv

Prerequisites:
    pip install netmiko
"""

import argparse
import csv
import logging
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
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
class FirmwareResult:
    host: str
    device_type: str
    detected_version: str = ""
    min_version: str = ""
    compliant: Optional[bool] = None
    error: str = ""
    model: str = ""
    raw_version_line: str = field(default="", repr=False)


def _version_tuple(version_str: str) -> tuple:
    """Convert dotted version string to comparable integer tuple."""
    parts = re.findall(r"\d+", version_str)
    return tuple(int(p) for p in parts)


def parse_version(show_version_output: str) -> tuple[str, str]:
    """Extract firmware version and model from 'show version' output."""
    version = ""
    model = ""

    version_patterns = [
        r"Cisco IOS Software.*?Version\s+([\d\w().]+)",
        r"Cisco IOS XE Software.*?Version\s+([\d\w().]+)",
        r"system:\s+version\s+([\d\w().]+)",
        r"NXOS:\s+version\s+([\d\w().]+)",
        r"Software.*?Version\s+([\d\w().]+)",
    ]
    for pattern in version_patterns:
        m = re.search(pattern, show_version_output, re.IGNORECASE)
        if m:
            version = m.group(1).strip("()")
            break

    model_patterns = [
        r"Model Number\s*:\s*(\S+)",
        r"cisco\s+([\w-]+)\s+processor",
        r"Hardware\s*:\s*\S+\s+([\w-]+),",
    ]
    for pattern in model_patterns:
        m = re.search(pattern, show_version_output, re.IGNORECASE)
        if m:
            model = m.group(1)
            break

    return version, model


def check_device(
    host: str,
    username: str,
    password: str,
    device_type: str,
    min_version: str,
    port: int = 22,
    timeout: int = 30,
    secret: str = "",
) -> FirmwareResult:
    result = FirmwareResult(host=host, device_type=device_type, min_version=min_version)
    device_params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "timeout": timeout,
    }
    if secret:
        device_params["secret"] = secret

    try:
        log.info("Connecting to %s (%s)", host, device_type)
        with ConnectHandler(**device_params) as conn:
            output = conn.send_command("show version")
        version, model = parse_version(output)
        result.detected_version = version
        result.model = model
        result.raw_version_line = output[:200]

        if not version:
            result.error = "Could not parse version from output"
        elif min_version:
            result.compliant = _version_tuple(version) >= _version_tuple(min_version)
        else:
            result.compliant = None

    except NetmikoAuthenticationException:
        result.error = "Authentication failed"
        log.error("%s: authentication failed", host)
    except NetmikoTimeoutException:
        result.error = "Connection timed out"
        log.error("%s: connection timed out", host)
    except Exception as exc:
        result.error = str(exc)
        log.error("%s: %s", host, exc)

    return result


def load_inventory(path: str) -> list[dict]:
    devices = []
    with open(path, newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            devices.append({k.strip(): v.strip() for k, v in row.items()})
    return devices


def print_report(results: list[FirmwareResult]) -> None:
    header = f"{'Host':<20} {'Model':<18} {'Detected':<18} {'Minimum':<18} {'Status'}"
    print("\n" + "=" * len(header))
    print(f"Firmware Compliance Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * len(header))
    print(header)
    print("-" * len(header))
    for r in results:
        if r.error:
            status = f"ERROR: {r.error}"
        elif r.compliant is True:
            status = "PASS"
        elif r.compliant is False:
            status = "FAIL"
        else:
            status = "UNCHECKED"
        print(f"{r.host:<20} {r.model:<18} {r.detected_version:<18} {r.min_version:<18} {status}")
    print("=" * len(header))
    passed = sum(1 for r in results if r.compliant is True)
    failed = sum(1 for r in results if r.compliant is False)
    errors = sum(1 for r in results if r.error)
    print(f"Summary: {passed} PASS  {failed} FAIL  {errors} ERROR  ({len(results)} total)\n")


def write_csv(results: list[FirmwareResult], path: str) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["host", "device_type", "model", "detected_version", "min_version", "compliant", "error"])
        for r in results:
            writer.writerow([r.host, r.device_type, r.model, r.detected_version, r.min_version,
                             "" if r.compliant is None else r.compliant, r.error])
    log.info("Report written to %s", path)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Check firmware compliance across network devices")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("-H", "--host", help="Single device IP or hostname")
    group.add_argument("--inventory", help="CSV inventory file (host,device_type,username,password,min_version)")
    p.add_argument("-u", "--username", help="SSH username (single-device mode)")
    p.add_argument("-p", "--password", help="SSH password (single-device mode)")
    p.add_argument("--secret", default="", help="Enable secret (optional)")
    p.add_argument("--device-type", default="cisco_ios", help="Netmiko device type (default: cisco_ios)")
    p.add_argument("--min-version", default="", help="Minimum required firmware version (e.g. 15.2.7)")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=30, help="Connection timeout in seconds (default: 30)")
    p.add_argument("--output", help="Write results to CSV file")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    results: list[FirmwareResult] = []

    if args.host:
        if not args.username or not args.password:
            parser.error("--username and --password are required for single-device mode")
        results.append(check_device(
            host=args.host,
            username=args.username,
            password=args.password,
            device_type=args.device_type,
            min_version=args.min_version,
            port=args.port,
            timeout=args.timeout,
            secret=args.secret,
        ))
    else:
        try:
            inventory = load_inventory(args.inventory)
        except FileNotFoundError:
            log.error("Inventory file not found: %s", args.inventory)
            sys.exit(1)

        for device in inventory:
            results.append(check_device(
                host=device.get("host", ""),
                username=device.get("username", ""),
                password=device.get("password", ""),
                device_type=device.get("device_type", "cisco_ios"),
                min_version=device.get("min_version", args.min_version),
                port=int(device.get("port", args.port)),
                timeout=args.timeout,
                secret=device.get("secret", args.secret),
            ))

    print_report(results)

    if args.output:
        write_csv(results, args.output)

    failures = [r for r in results if r.compliant is False or r.error]
    sys.exit(1 if failures else 0)
```