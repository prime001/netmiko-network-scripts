firmware_compliance.py - Network device firmware compliance auditor.

Connects to one or more network devices via SSH (netmiko), retrieves the
running firmware/OS version, and compares it against a user-supplied policy
that maps device platform to a minimum acceptable version string.

Prerequisites:
    pip install netmiko pyyaml

Usage:
    # Single device check
    python firmware_compliance.py --host 192.168.1.1 --device-type cisco_ios \
        --username admin --password secret --policy policy.yaml

    # Batch check from CSV (columns: host,device_type,username,password)
    python firmware_compliance.py --inventory devices.csv --policy policy.yaml \
        --output report.csv

Policy file (YAML) example:
    cisco_ios: "15.2"
    cisco_nxos: "9.3"
    cisco_xe: "17.3"
    juniper_junos: "20.2"

Exit codes:
    0 - All devices compliant
    1 - One or more devices non-compliant or unreachable
"""

import argparse
import csv
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

VERSION_COMMANDS = {
    "cisco_ios": "show version",
    "cisco_xe": "show version",
    "cisco_nxos": "show version",
    "cisco_xr": "show version",
    "juniper_junos": "show version",
    "arista_eos": "show version",
    "hp_comware": "display version",
}

VERSION_PATTERNS = {
    "cisco_ios": r"Cisco IOS Software.*Version\s+(\S+),",
    "cisco_xe": r"Cisco IOS XE Software.*Version\s+(\S+)",
    "cisco_nxos": r"NXOS:\s+version\s+(\S+)",
    "cisco_xr": r"Cisco IOS XR Software.*Version\s+(\S+)",
    "juniper_junos": r"Junos:\s+(\S+)",
    "arista_eos": r"EOS version:\s+(\S+)",
    "hp_comware": r"Software Version\s+(\S+)",
}


@dataclass
class DeviceResult:
    host: str
    device_type: str
    current_version: Optional[str] = None
    required_version: Optional[str] = None
    compliant: Optional[bool] = None
    error: Optional[str] = None


def load_policy(policy_file: str) -> dict:
    path = Path(policy_file)
    if not path.exists():
        logger.error("Policy file not found: %s", policy_file)
        sys.exit(1)
    if not HAS_YAML:
        logger.error("pyyaml is required; pip install pyyaml")
        sys.exit(1)
    with open(path) as f:
        return yaml.safe_load(f) or {}


def load_inventory(csv_file: str) -> List[dict]:
    path = Path(csv_file)
    if not path.exists():
        logger.error("Inventory file not found: %s", csv_file)
        sys.exit(1)
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def extract_version(output: str, device_type: str) -> Optional[str]:
    pattern = VERSION_PATTERNS.get(device_type)
    if not pattern:
        return None
    match = re.search(pattern, output, re.IGNORECASE)
    return match.group(1).rstrip(",") if match else None


def is_version_compliant(current: str, required: str) -> bool:
    def normalize(v):
        return [int(x) if x.isdigit() else x for x in re.split(r"[.()\-]", v) if x]

    try:
        return normalize(current) >= normalize(required)
    except TypeError:
        return current >= required


def check_device(host: str, device_type: str, username: str, password: str,
                 policy: dict, port: int = 22) -> DeviceResult:
    result = DeviceResult(host=host, device_type=device_type)
    result.required_version = policy.get(device_type)

    command = VERSION_COMMANDS.get(device_type)
    if not command:
        result.error = f"Unsupported device type: {device_type}"
        logger.warning("[%s] %s", host, result.error)
        return result

    logger.info("[%s] Connecting (%s)", host, device_type)
    try:
        with ConnectHandler(
            device_type=device_type,
            host=host,
            port=port,
            username=username,
            password=password,
            timeout=30,
            session_timeout=60,
        ) as conn:
            output = conn.send_command(command, read_timeout=30)

        result.current_version = extract_version(output, device_type)
        if result.current_version is None:
            result.error = "Could not parse version from output"
            logger.warning("[%s] %s", host, result.error)
        elif result.required_version:
            result.compliant = is_version_compliant(
                result.current_version, result.required_version
            )
            status = "COMPLIANT" if result.compliant else "NON-COMPLIANT"
            logger.info(
                "[%s] %s — current=%s required>=%s",
                host, status, result.current_version, result.required_version,
            )
        else:
            logger.info("[%s] version=%s (no policy defined for %s)",
                        host, result.current_version, device_type)

    except NetmikoAuthenticationException:
        result.error = "Authentication failed"
        logger.error("[%s] %s", host, result.error)
    except NetmikoTimeoutException:
        result.error = "Connection timed out"
        logger.error("[%s] %s", host, result.error)
    except Exception as exc:
        result.error = str(exc)
        logger.error("[%s] Unexpected error: %s", host, exc)

    return result


def write_report(results: List[DeviceResult], output_file: str) -> None:
    fieldnames = ["host", "device_type", "current_version",
                  "required_version", "compliant", "error"]
    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "host": r.host,
                "device_type": r.device_type,
                "current_version": r.current_version or "",
                "required_version": r.required_version or "",
                "compliant": "" if r.compliant is None else str(r.compliant),
                "error": r.error or "",
            })
    logger.info("Report written to %s", output_file)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit network device firmware compliance against a version policy.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--host", help="Single device IP/hostname")
    target.add_argument("--inventory", help="CSV file (columns: host,device_type,username,password)")

    parser.add_argument("--device-type", default="cisco_ios",
                        choices=list(VERSION_COMMANDS.keys()),
                        help="Netmiko device type for single-host mode")
    parser.add_argument("--username", help="SSH username (single-host mode)")
    parser.add_argument("--password", help="SSH password (single-host mode)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--policy", required=True,
                        help="YAML file mapping device_type to minimum required version")
    parser.add_argument("--output", help="Write results to this CSV file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    policy = load_policy(args.policy)

    devices = []
    if args.host:
        if not args.username or not args.password:
            parser.error("--username and --password are required with --host")
        devices.append({
            "host": args.host,
            "device_type": args.device_type,
            "username": args.username,
            "password": args.password,
            "port": str(args.port),
        })
    else:
        devices = load_inventory(args.inventory)

    results = []
    for dev in devices:
        result = check_device(
            host=dev["host"],
            device_type=dev.get("device_type", "cisco_ios"),
            username=dev["username"],
            password=dev["password"],
            policy=policy,
            port=int(dev.get("port", args.port)),
        )
        results.append(result)

    if args.output:
        write_report(results, args.output)

    non_compliant = sum(1 for r in results if r.compliant is False or r.error)
    logger.info("Summary: %d checked, %d non-compliant/error", len(results), non_compliant)
    return 1 if non_compliant else 0


if __name__ == "__main__":
    sys.exit(main())