The working directory is `/opt/NetAutoCommitter` (a different project). The netmiko scripts live in a separate portfolio repo — I'll write the script content directly as requested, targeting `023_firmware_check.py`.

```python
"""
023_firmware_check.py — Multi-vendor firmware compliance checker.

Connects to network devices via SSH, retrieves the running OS version, and
compares it against a minimum acceptable version defined in policy. Produces
a per-device pass/fail compliance report and exits non-zero when any device
is out of compliance or unreachable.

Usage:
    # Single device
    python 023_firmware_check.py -H 10.0.0.1 -u admin -p secret \
        --device-type cisco_ios --min-version "15.9(3)M6"

    # CSV inventory  (columns: host, device_type, min_version)
    python 023_firmware_check.py --inventory devices.csv -u admin -p secret

    # JSON output
    python 023_firmware_check.py --inventory devices.csv -u admin -p secret --json

Prerequisites:
    pip install netmiko
    Read-only (privilege level ≥ 1) SSH credentials on each device.

Supported device types: cisco_ios, cisco_xe, cisco_nxos, cisco_xr
"""

import argparse
import csv
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

_SHOW_CMD = {
    "cisco_ios": "show version",
    "cisco_xe": "show version",
    "cisco_nxos": "show version",
    "cisco_xr": "show version brief",
}

_VERSION_RE = {
    "cisco_ios": re.compile(r"Cisco IOS Software.*?Version\s+(\S+),", re.DOTALL),
    "cisco_xe": re.compile(r"Cisco IOS XE Software.*?Version\s+(\S+)", re.DOTALL),
    "cisco_nxos": re.compile(r"(?:NXOS|system):\s+version\s+(\S+)", re.IGNORECASE),
    "cisco_xr": re.compile(r"Cisco IOS XR Software.*?Version\s+(\S+)", re.DOTALL),
}


def _version_key(v: str) -> tuple:
    """Decompose a version string into a sortable tuple of ints and strings."""
    return tuple(int(p) if p.isdigit() else p for p in re.split(r"[.()\-]", v) if p)


@dataclass
class Result:
    host: str
    device_type: str
    min_version: str
    running_version: Optional[str] = None
    compliant: Optional[bool] = None
    error: Optional[str] = None
    checked_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _fetch_version(conn, device_type: str) -> Optional[str]:
    output = conn.send_command(_SHOW_CMD[device_type])
    m = _VERSION_RE[device_type].search(output)
    return m.group(1).rstrip(",") if m else None


def check_device(
    host: str,
    username: str,
    password: str,
    device_type: str,
    min_version: str,
    port: int = 22,
    timeout: int = 30,
) -> Result:
    result = Result(host=host, device_type=device_type, min_version=min_version)
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "timeout": timeout,
    }
    try:
        log.info("Connecting to %s (%s) …", host, device_type)
        with ConnectHandler(**params) as conn:
            running = _fetch_version(conn, device_type)
        if running is None:
            result.error = "Version string not found in output"
            log.warning("%s: %s", host, result.error)
            return result
        result.running_version = running
        result.compliant = _version_key(running) >= _version_key(min_version)
        badge = "PASS" if result.compliant else "FAIL"
        log.info("%s  running=%s  min=%s  [%s]", host, running, min_version, badge)
    except NetmikoAuthenticationException:
        result.error = "Authentication failed"
        log.error("%s: %s", host, result.error)
    except NetmikoTimeoutException:
        result.error = "Connection timed out"
        log.error("%s: %s", host, result.error)
    except Exception as exc:
        result.error = str(exc)
        log.error("%s: %s", host, exc)
    return result


def load_inventory(path: str) -> list:
    with open(path, newline="") as fh:
        return [{k.strip(): v.strip() for k, v in row.items()} for row in csv.DictReader(fh)]


def print_table(results: list) -> None:
    col = {"host": 22, "running": 20, "min": 20, "status": 30}
    hdr = (
        f"{'HOST':<{col['host']}}  {'RUNNING':<{col['running']}}"
        f"  {'MIN REQUIRED':<{col['min']}}  STATUS"
    )
    bar = "─" * (len(hdr) + 4)
    print(f"\n{bar}\n{hdr}\n{bar}")
    for r in results:
        if r.error:
            status = f"ERROR — {r.error}"
        elif r.compliant:
            status = "PASS"
        else:
            status = "FAIL"
        running = r.running_version or "—"
        print(
            f"{r.host:<{col['host']}}  {running:<{col['running']}}"
            f"  {r.min_version:<{col['min']}}  {status}"
        )
    print(f"{bar}\n")
    total = len(results)
    passed = sum(1 for r in results if r.compliant)
    failed = sum(1 for r in results if r.compliant is False)
    errors = sum(1 for r in results if r.error)
    print(f"Summary: {total} devices  |  {passed} pass  |  {failed} fail  |  {errors} error\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Check firmware versions against a minimum-version compliance policy.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    single = p.add_argument_group("single device")
    single.add_argument("-H", "--host", metavar="HOST")
    single.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(_SHOW_CMD),
        metavar="TYPE",
        help="cisco_ios | cisco_xe | cisco_nxos | cisco_xr  (default: cisco_ios)",
    )
    single.add_argument("--min-version", metavar="VER", help="Minimum acceptable version string")

    inv = p.add_argument_group("inventory mode")
    inv.add_argument("--inventory", metavar="FILE", help="CSV file: host,device_type,min_version")

    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--timeout", type=int, default=30, metavar="SEC")
    p.add_argument("--json", dest="json_out", action="store_true", help="Emit JSON report")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.inventory:
        inventory = load_inventory(args.inventory)
    elif args.host and args.min_version:
        inventory = [
            {"host": args.host, "device_type": args.device_type, "min_version": args.min_version}
        ]
    else:
        parser.error("Provide --host + --min-version for a single device, or --inventory for bulk.")

    results = [
        check_device(
            host=entry["host"],
            username=args.username,
            password=args.password,
            device_type=entry.get("device_type", "cisco_ios"),
            min_version=entry["min_version"],
            port=args.port,
            timeout=args.timeout,
        )
        for entry in inventory
    ]

    if args.json_out:
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        print_table(results)

    sys.exit(0 if all(r.compliant for r in results) else 1)
```