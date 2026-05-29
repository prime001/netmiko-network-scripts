NTP Compliance Checker

Connects to network devices via SSH and verifies NTP synchronization status,
checking stratum level, reference clock association, and clock offset against
configurable compliance thresholds.

Usage:
    python ntp_compliance.py -d 192.168.1.1 -u admin -p secret
    python ntp_compliance.py -d 192.168.1.1 -u admin --device-type cisco_nxos
    python ntp_compliance.py --host-file devices.txt -u admin --max-stratum 3

Prerequisites:
    pip install netmiko
"""

import argparse
import getpass
import logging
import re
import sys

from netmiko import ConnectHandler
from netmiko.exceptions import NetMikoAuthenticationException, NetMikoTimeoutException


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


NTP_STATUS_COMMANDS = {
    "cisco_ios": "show ntp status",
    "cisco_xe": "show ntp status",
    "cisco_nxos": "show ntp status",
    "cisco_xr": "show ntp status",
    "arista_eos": "show ntp status",
    "juniper_junos": "show ntp status",
}


def parse_ntp_status(output: str) -> dict:
    result = {"synced": False, "stratum": None, "reference": None, "offset_ms": None}

    if re.search(r"clock is synchronized", output, re.IGNORECASE):
        result["synced"] = True
    elif re.search(r"synchronised\s+to", output, re.IGNORECASE):
        result["synced"] = True

    match = re.search(r"stratum\s+(\d+)", output, re.IGNORECASE)
    if match:
        result["stratum"] = int(match.group(1))

    match = re.search(
        r"reference\s+(?:is\s+)?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[0-9A-Fa-f:.]+)",
        output,
        re.IGNORECASE,
    )
    if match:
        result["reference"] = match.group(1)

    match = re.search(r"offset\s+(?:is\s+)?([+-]?\d+\.?\d*)\s*ms", output, re.IGNORECASE)
    if match:
        result["offset_ms"] = float(match.group(1))

    return result


def check_device(
    host: str,
    username: str,
    password: str,
    device_type: str,
    port: int,
    max_stratum: int,
    max_offset_ms: float,
) -> dict:
    result = {
        "host": host,
        "compliant": False,
        "synced": False,
        "stratum": None,
        "offset_ms": None,
        "reference": None,
        "issues": [],
        "error": None,
    }

    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
    }

    try:
        logger.info("Connecting to %s", host)
        with ConnectHandler(**params) as conn:
            cmd = NTP_STATUS_COMMANDS.get(device_type, "show ntp status")
            output = conn.send_command(cmd)
            logger.debug("NTP status for %s:\n%s", host, output)

        parsed = parse_ntp_status(output)
        result.update(parsed)

        issues = []
        if not result["synced"]:
            issues.append("not synchronized")
        if result["stratum"] is not None and result["stratum"] > max_stratum:
            issues.append(f"stratum {result['stratum']} exceeds max {max_stratum}")
        if result["offset_ms"] is not None and abs(result["offset_ms"]) > max_offset_ms:
            issues.append(
                f"offset {result['offset_ms']}ms exceeds {max_offset_ms}ms limit"
            )

        result["issues"] = issues
        result["compliant"] = result["synced"] and len(issues) == 0

    except NetMikoAuthenticationException:
        result["error"] = "authentication failed"
        logger.error("Authentication failed for %s", host)
    except NetMikoTimeoutException:
        result["error"] = "connection timed out"
        logger.error("Timeout connecting to %s", host)
    except Exception as exc:
        result["error"] = str(exc)
        logger.error("Unexpected error on %s: %s", host, exc)

    return result


def print_report(results: list) -> None:
    compliant_count = sum(1 for r in results if r["compliant"])
    total = len(results)

    print(f"\n{'=' * 60}")
    print(f"NTP Compliance Report  {compliant_count}/{total} compliant")
    print(f"{'=' * 60}")

    for r in results:
        tag = "PASS" if r["compliant"] else "FAIL"
        print(f"\n[{tag}] {r['host']}")
        if r["error"]:
            print(f"  ERROR: {r['error']}")
            continue
        print(f"  Synchronized : {r['synced']}")
        print(
            f"  Stratum      : {r['stratum'] if r['stratum'] is not None else 'unknown'}"
        )
        print(f"  Reference    : {r['reference'] or 'unknown'}")
        if r["offset_ms"] is not None:
            print(f"  Offset       : {r['offset_ms']} ms")
        else:
            print("  Offset       : unknown")
        for issue in r["issues"]:
            print(f"  Issue        : {issue}")

    print(f"\n{'=' * 60}\n")


def load_hosts(host_file: str) -> list:
    try:
        with open(host_file) as fh:
            return [
                line.strip()
                for line in fh
                if line.strip() and not line.strip().startswith("#")
            ]
    except FileNotFoundError:
        logger.error("Host file not found: %s", host_file)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify NTP synchronization compliance on network devices"
    )

    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--device", help="Single device IP or hostname")
    target.add_argument("--host-file", help="File containing one device per line")

    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(NTP_STATUS_COMMANDS.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--max-stratum",
        type=int,
        default=5,
        help="Maximum acceptable NTP stratum (default: 5)",
    )
    parser.add_argument(
        "--max-offset",
        type=float,
        default=100.0,
        help="Maximum acceptable clock offset in milliseconds (default: 100.0)",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop after the first non-compliant device",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable debug logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.username}: ")

    hosts = [args.device] if args.device else load_hosts(args.host_file)

    results = []
    for host in hosts:
        result = check_device(
            host=host,
            username=args.username,
            password=password,
            device_type=args.device_type,
            port=args.port,
            max_stratum=args.max_stratum,
            max_offset_ms=args.max_offset,
        )
        results.append(result)
        if args.fail_fast and not result["compliant"]:
            logger.warning("Fail-fast triggered on %s", host)
            break

    print_report(results)
    sys.exit(0 if all(r["compliant"] for r in results) else 1)


if __name__ == "__main__":
    main()