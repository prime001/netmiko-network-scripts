```python
"""
firmware_compliance_audit.py - Firmware compliance policy auditor for network devices.

Reads a JSON policy file defining approved firmware versions per platform, connects
to one or more devices, and produces a compliance report (JSON or CSV).

Usage:
    # Single device
    python firmware_compliance_audit.py --host 192.168.1.1 --username admin \
        --password secret --device-type cisco_ios --policy policy.json

    # Inventory file (one host per line: host,device_type)
    python firmware_compliance_audit.py --inventory devices.csv \
        --username admin --password secret --policy policy.json --output report.json

Prerequisites:
    pip install netmiko
    Python 3.8+

Policy file format (policy.json):
    {
        "cisco_ios":    {"approved": ["15.9(3)M3", "16.12.5"], "min": "15.9"},
        "cisco_nxos":   {"approved": ["9.3(8)", "10.2(3)"],    "min": "9.3"},
        "arista_eos":   {"approved": ["4.28.2F", "4.29.1F"],   "min": "4.28"}
    }
"""

import argparse
import csv
import json
import logging
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

VERSION_COMMANDS = {
    "cisco_ios": "show version | include Version",
    "cisco_nxos": "show version | include NXOS",
    "cisco_xr": "show version | include Version",
    "arista_eos": "show version | include Software image version",
    "juniper_junos": "show version | match Junos",
}


@dataclass
class AuditResult:
    host: str
    device_type: str
    current_version: str = ""
    compliant: bool = False
    in_approved_list: bool = False
    meets_minimum: bool = False
    error: str = ""
    raw_output: str = field(default="", repr=False)


def get_firmware_version(connection, device_type: str) -> str:
    cmd = VERSION_COMMANDS.get(device_type, "show version")
    output = connection.send_command(cmd, read_timeout=30)
    # Extract the version token — typically the last whitespace-delimited field
    for line in output.splitlines():
        line = line.strip()
        if line:
            parts = line.split()
            return parts[-1].strip(",")
    return output.strip()


def version_meets_minimum(current: str, minimum: str) -> bool:
    """Naive numeric prefix comparison — good enough for IOS/EOS/NX-OS."""
    def numeric_parts(v):
        import re
        return [int(x) for x in re.findall(r"\d+", v)]

    try:
        return numeric_parts(current) >= numeric_parts(minimum)
    except (ValueError, TypeError):
        return False


def audit_device(host: str, device_type: str, username: str, password: str,
                 policy: dict, port: int = 22) -> AuditResult:
    result = AuditResult(host=host, device_type=device_type)
    platform_policy = policy.get(device_type, {})

    device_params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "timeout": 20,
        "session_timeout": 60,
    }

    try:
        log.info("Connecting to %s (%s)", host, device_type)
        with ConnectHandler(**device_params) as conn:
            result.raw_output = get_firmware_version(conn, device_type)
            result.current_version = result.raw_output

        approved = platform_policy.get("approved", [])
        minimum = platform_policy.get("min", "")

        result.in_approved_list = result.current_version in approved
        result.meets_minimum = (
            version_meets_minimum(result.current_version, minimum) if minimum else True
        )
        result.compliant = result.in_approved_list and result.meets_minimum

        status = "COMPLIANT" if result.compliant else "NON-COMPLIANT"
        log.info("%s %s — version=%s status=%s", host, device_type,
                 result.current_version, status)

    except NetmikoAuthenticationException:
        result.error = "authentication_failed"
        log.error("%s authentication failed", host)
    except NetmikoTimeoutException:
        result.error = "timeout"
        log.error("%s connection timed out", host)
    except Exception as exc:  # noqa: BLE001
        result.error = str(exc)
        log.error("%s unexpected error: %s", host, exc)

    return result


def write_report(results: list[AuditResult], output_path: str) -> None:
    path = Path(output_path)
    data = [asdict(r) for r in results]

    if path.suffix.lower() == ".csv":
        keys = list(data[0].keys()) if data else []
        with path.open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=keys)
            writer.writeheader()
            writer.writerows(d for d in data)
    else:
        path.write_text(json.dumps(data, indent=2))

    log.info("Report written to %s", output_path)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Audit network device firmware compliance against a policy file."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--host", help="Single device IP or hostname")
    target.add_argument("--inventory", help="CSV file: host,device_type (one per line)")
    parser.add_argument("--device-type", default="cisco_ios",
                        help="Netmiko device type (single host mode)")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--policy", required=True, help="Path to JSON policy file")
    parser.add_argument("--output", default="firmware_audit.json",
                        help="Output file (.json or .csv)")
    return parser.parse_args()


def load_inventory(path: str) -> list[tuple[str, str]]:
    entries = []
    with open(path) as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            host = row[0].strip()
            dtype = row[1].strip() if len(row) > 1 else "cisco_ios"
            entries.append((host, dtype))
    return entries


if __name__ == "__main__":
    args = parse_args()

    policy = json.loads(Path(args.policy).read_text())

    if args.host:
        targets = [(args.host, args.device_type)]
    else:
        targets = load_inventory(args.inventory)

    if not targets:
        log.error("No targets to audit.")
        sys.exit(1)

    results = [
        audit_device(host, dtype, args.username, args.password, policy, args.port)
        for host, dtype in targets
    ]

    compliant = sum(1 for r in results if r.compliant)
    log.info("Audit complete: %d/%d devices compliant", compliant, len(results))

    write_report(results, args.output)

    non_compliant = [r for r in results if not r.compliant]
    if non_compliant:
        log.warning("Non-compliant devices: %s",
                    ", ".join(r.host for r in non_compliant))
        sys.exit(2)
```