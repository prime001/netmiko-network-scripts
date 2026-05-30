The write was blocked by permissions. Here is the script content as requested:

"""interface_error_monitor.py — Interface error counter auditor for Cisco IOS/IOS-XE.

Connects to a network device, collects per-interface error counters (input
errors, CRC, output drops, runts, giants), and flags any interface that
exceeds configurable thresholds. Exits with code 1 when violations are found
so the script integrates cleanly with monitoring systems and cron jobs.

Usage:
    python interface_error_monitor.py -d 10.0.0.1 -u admin -p secret
    python interface_error_monitor.py -d 10.0.0.1 -u admin -p secret \
        --error-threshold 100 --drop-threshold 50 --json
    python interface_error_monitor.py -d 10.0.0.1 -u admin -p secret \
        --device-type cisco_xe --port 830 --verbose

Prerequisites:
    pip install netmiko
"""

import argparse
import json
import logging
import re
import sys
from typing import Any

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

COUNTER_PATTERNS: dict[str, re.Pattern] = {
    "input_errors": re.compile(r"(\d+)\s+input errors"),
    "crc": re.compile(r"(\d+)\s+CRC"),
    "output_drops": re.compile(r"(\d+)\s+output drops"),
    "input_drops": re.compile(r"(\d+)\s+input drops"),
    "runts": re.compile(r"(\d+)\s+runts"),
    "giants": re.compile(r"(\d+)\s+giants"),
}


def parse_interface_errors(raw_output: str) -> list[dict[str, Any]]:
    """Parse show interfaces output into per-interface error counter dicts."""
    results: list[dict[str, Any]] = []
    current_name: str | None = None
    current_lines: list[str] = []

    for line in raw_output.splitlines():
        if re.match(r"^\S", line) and " is " in line:
            if current_name and current_lines:
                block = "\n".join(current_lines)
                entry: dict[str, Any] = {"interface": current_name}
                for key, pattern in COUNTER_PATTERNS.items():
                    m = pattern.search(block)
                    entry[key] = int(m.group(1)) if m else 0
                results.append(entry)
            current_name = line.split()[0]
            current_lines = [line]
        elif current_name is not None:
            current_lines.append(line)

    if current_name and current_lines:
        block = "\n".join(current_lines)
        entry = {"interface": current_name}
        for key, pattern in COUNTER_PATTERNS.items():
            m = pattern.search(block)
            entry[key] = int(m.group(1)) if m else 0
        results.append(entry)

    return results


def find_violations(
    interfaces: list[dict[str, Any]],
    error_threshold: int,
    drop_threshold: int,
) -> list[dict[str, Any]]:
    """Return interfaces whose counters exceed the given thresholds."""
    violations: list[dict[str, Any]] = []
    for intf in interfaces:
        reasons: list[str] = []
        for counter in ("input_errors", "crc", "runts", "giants"):
            if intf[counter] >= error_threshold:
                reasons.append(f"{counter}={intf[counter]} >= {error_threshold}")
        for counter in ("output_drops", "input_drops"):
            if intf[counter] >= drop_threshold:
                reasons.append(f"{counter}={intf[counter]} >= {drop_threshold}")
        if reasons:
            violations.append({**intf, "violations": reasons})
    return violations


def audit_device(args: argparse.Namespace) -> int:
    """Connect, collect, evaluate, and report. Returns exit code."""
    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "timeout": args.timeout,
    }

    logger.info("Connecting to %s as %s", args.device, args.username)
    try:
        with ConnectHandler(**device_params) as conn:
            logger.info("Sending 'show interfaces'")
            raw = conn.send_command("show interfaces", read_timeout=60)
    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s", args.device)
        return 2
    except NetmikoTimeoutException:
        logger.error("Connection timed out: %s", args.device)
        return 2
    except Exception as exc:
        logger.error("Unexpected connection error: %s", exc)
        return 2

    interfaces = parse_interface_errors(raw)
    logger.info("Parsed %d interfaces", len(interfaces))

    violations = find_violations(interfaces, args.error_threshold, args.drop_threshold)

    if args.json:
        report = {
            "device": args.device,
            "total_interfaces": len(interfaces),
            "violation_count": len(violations),
            "thresholds": {
                "error_threshold": args.error_threshold,
                "drop_threshold": args.drop_threshold,
            },
            "violations": violations,
        }
        print(json.dumps(report, indent=2))
    elif violations:
        print(f"\nINTERFACE ERROR VIOLATIONS — {args.device}")
        print("-" * 60)
        for v in violations:
            print(f"  {v['interface']}")
            for reason in v["violations"]:
                print(f"    - {reason}")
        print()
    else:
        print(
            f"OK: all {len(interfaces)} interfaces within thresholds on {args.device}"
        )

    return 1 if violations else 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit interface error counters and alert on threshold breaches."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument(
        "-t",
        "--device-type",
        default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--timeout", type=int, default=30, help="Connection timeout in seconds (default: 30)"
    )
    parser.add_argument(
        "--error-threshold",
        type=int,
        default=50,
        help="Flag input_errors/CRC/runts/giants >= this value (default: 50)",
    )
    parser.add_argument(
        "--drop-threshold",
        type=int,
        default=100,
        help="Flag input/output drops >= this value (default: 100)",
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit results as JSON (useful for monitoring pipelines)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable DEBUG logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    sys.exit(audit_device(args))


if __name__ == "__main__":
    main()