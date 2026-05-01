```python
"""
firmware_compliance_audit.py — Audit device firmware versions against a policy baseline.

Purpose:
    Connect to one or more network devices, retrieve the running firmware version,
    and compare it against a minimum-required version defined in a policy file.
    Exits non-zero when any device is out of compliance, making it CI/CD-friendly.

Usage:
    # Single device
    python firmware_compliance_audit.py \\
        --host 192.168.1.1 --device-type cisco_ios \\
        --username admin --password secret \\
        --min-version 15.2(7)E3

    # Inventory file (CSV: host,device_type,min_version)
    python firmware_compliance_audit.py \\
        --inventory devices.csv \\
        --username admin --password secret \\
        --report audit_report.csv

Prerequisites:
    pip install netmiko
    CSV columns (when using --inventory): host, device_type, min_version
    Supported device_type values: cisco_ios, cisco_nxos, cisco_xr, juniper_junos
"""

import argparse
import csv
import logging
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


VERSION_COMMANDS = {
    "cisco_ios": "show version",
    "cisco_ios_xe": "show version",
    "cisco_nxos": "show version",
    "cisco_xr": "show version",
    "juniper_junos": "show version",
}

VERSION_PATTERNS = {
    "cisco_ios":    r"(?:IOS Software.*?Version\s+|Version\s+)([^\s,]+)",
    "cisco_ios_xe": r"(?:IOS-XE Software.*?Version\s+|Cisco IOS XE Software, Version\s+)([^\s,]+)",
    "cisco_nxos":   r"NXOS:\s+version\s+(\S+)",
    "cisco_xr":     r"Cisco IOS XR Software, Version\s+(\S+)",
    "juniper_junos": r"Junos:\s+(\S+)",
}


@dataclass
class DeviceResult:
    host: str
    device_type: str
    min_version: str
    running_version: str = ""
    compliant: Optional[bool] = None
    error: str = ""
    duration_s: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


def _version_tuple(version_str: str) -> tuple:
    """Convert version string to comparable tuple of ints/strings."""
    parts = re.split(r"[.()\[\]]", version_str)
    result = []
    for p in parts:
        if p == "":
            continue
        try:
            result.append(int(p))
        except ValueError:
            result.append(p.lower())
    return tuple(result)


def is_compliant(running: str, minimum: str) -> bool:
    return _version_tuple(running) >= _version_tuple(minimum)


def extract_version(output: str, device_type: str) -> str:
    pattern = VERSION_PATTERNS.get(device_type)
    if not pattern:
        raise ValueError(f"No version pattern defined for device_type '{device_type}'")
    match = re.search(pattern, output, re.IGNORECASE)
    if not match:
        raise ValueError(f"Version string not found in output (pattern: {pattern})")
    return match.group(1)


def audit_device(host: str, device_type: str, username: str, password: str,
                 min_version: str, port: int = 22, timeout: int = 30) -> DeviceResult:
    result = DeviceResult(host=host, device_type=device_type, min_version=min_version)
    start = datetime.utcnow()
    try:
        log.info("[%s] Connecting (%s)", host, device_type)
        with ConnectHandler(
            device_type=device_type,
            host=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            session_log=None,
        ) as conn:
            command = VERSION_COMMANDS.get(device_type, "show version")
            output = conn.send_command(command)

        result.running_version = extract_version(output, device_type)
        result.compliant = is_compliant(result.running_version, min_version)
        status = "COMPLIANT" if result.compliant else "NON-COMPLIANT"
        log.info("[%s] %s — running=%s  min=%s", host, status,
                 result.running_version, min_version)

    except NetmikoAuthenticationException:
        result.error = "authentication failure"
        log.error("[%s] Authentication failure", host)
    except NetmikoTimeoutException:
        result.error = "connection timeout"
        log.error("[%s] Connection timed out", host)
    except ValueError as exc:
        result.error = str(exc)
        log.error("[%s] Parse error: %s", host, exc)
    except Exception as exc:  # noqa: BLE001
        result.error = str(exc)
        log.error("[%s] Unexpected error: %s", host, exc)
    finally:
        result.duration_s = (datetime.utcnow() - start).total_seconds()

    return result


def load_inventory(path: str) -> list[dict]:
    rows = []
    with open(path, newline="") as fh:
        reader = csv.DictReader(fh)
        required = {"host", "device_type", "min_version"}
        if not required.issubset(set(reader.fieldnames or [])):
            raise ValueError(f"Inventory CSV must contain columns: {required}")
        for row in reader:
            rows.append(row)
    return rows


def write_report(results: list[DeviceResult], path: str) -> None:
    fieldnames = ["host", "device_type", "min_version", "running_version",
                  "compliant", "error", "duration_s", "timestamp"]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "host": r.host,
                "device_type": r.device_type,
                "min_version": r.min_version,
                "running_version": r.running_version,
                "compliant": r.compliant,
                "error": r.error,
                "duration_s": f"{r.duration_s:.2f}",
                "timestamp": r.timestamp,
            })
    log.info("Report written to %s", path)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Audit network device firmware against minimum version policy."
    )
    single = p.add_argument_group("single-device mode")
    single.add_argument("--host", help="Device IP or hostname")
    single.add_argument("--device-type", default="cisco_ios",
                        choices=list(VERSION_COMMANDS.keys()),
                        help="Netmiko device type (default: cisco_ios)")
    single.add_argument("--min-version", help="Minimum acceptable firmware version")

    inv = p.add_argument_group("inventory mode")
    inv.add_argument("--inventory", help="CSV file with columns: host,device_type,min_version")

    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--report", help="Write CSV compliance report to this path")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if not args.inventory and not (args.host and args.min_version):
        parser.error("Provide --inventory OR both --host and --min-version")

    if args.inventory and not Path(args.inventory).is_file():
        parser.error(f"Inventory file not found: {args.inventory}")

    devices = []
    if args.inventory:
        try:
            devices = load_inventory(args.inventory)
        except (OSError, ValueError) as exc:
            log.error("Failed to load inventory: %s", exc)
            sys.exit(2)
    else:
        devices = [{"host": args.host, "device_type": args.device_type,
                    "min_version": args.min_version}]

    results: list[DeviceResult] = []
    for dev in devices:
        r = audit_device(
            host=dev["host"],
            device_type=dev["device_type"],
            username=args.username,
            password=args.password,
            min_version=dev["min_version"],
            port=args.port,
            timeout=args.timeout,
        )
        results.append(r)

    if args.report:
        write_report(results, args.report)

    non_compliant = [r for r in results if not r.compliant]
    errors = [r for r in results if r.error]

    print(f"\nSummary: {len(results)} device(s) checked — "
          f"{len(results) - len(non_compliant) - len(errors)} compliant, "
          f"{len(non_compliant)} non-compliant, {len(errors)} error(s)")

    for r in non_compliant:
        print(f"  NON-COMPLIANT  {r.host:<20} running={r.running_version}  min={r.min_version}")
    for r in errors:
        print(f"  ERROR          {r.host:<20} {r.error}")

    sys.exit(1 if non_compliant or errors else 0)
```