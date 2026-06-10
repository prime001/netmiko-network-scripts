```python
"""
ntp_sync_checker.py - NTP synchronization health checker for network devices.

Connects to a Cisco IOS/IOS-XE/NX-OS device via SSH and validates NTP
synchronization status: checks whether the clock is synchronized, validates
stratum level and clock offset against configurable thresholds, and reports
peer association count.

Usage:
    python ntp_sync_checker.py -d 192.168.1.1 -u admin
    python ntp_sync_checker.py -d 10.0.0.1 -u admin -p secret --device-type cisco_nxos
    python ntp_sync_checker.py -d 10.0.0.1 -u admin --max-stratum 3 --max-offset 50

Prerequisites:
    pip install netmiko

Exit codes:
    0 - All checks passed
    1 - Connection or authentication error
    2 - One or more NTP checks failed
"""

import argparse
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.WARNING)
logger = logging.getLogger(__name__)


def parse_ntp_status(output):
    """Extract sync state, stratum, offset, and reference from 'show ntp status'."""
    result = {"synchronized": False, "stratum": None, "offset": None, "reference": None}

    if re.search(r"Clock is synchronized", output, re.IGNORECASE):
        result["synchronized"] = True

    m = re.search(r"stratum\s+(\d+)", output, re.IGNORECASE)
    if m:
        result["stratum"] = int(m.group(1))

    m = re.search(r"offset\s+(?:is\s+)?([-\d.]+)", output, re.IGNORECASE)
    if m:
        result["offset"] = float(m.group(1))

    m = re.search(r"reference is\s+(\S+)", output, re.IGNORECASE)
    if m:
        result["reference"] = m.group(1)

    return result


def parse_ntp_peer_count(output):
    """Count configured NTP peers from 'show ntp associations'."""
    count = 0
    for line in output.splitlines():
        # Association lines begin with optional sync marker then an IP address
        if re.match(r"[\s~*#+]\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line):
            count += 1
    return count


def run_ntp_checks(connection, max_stratum, max_offset_ms):
    """Gather NTP data and evaluate against thresholds. Returns results dict."""
    results = {
        "synchronized": False,
        "stratum": None,
        "offset_ms": None,
        "reference": None,
        "peer_count": 0,
        "issues": [],
    }

    try:
        status_out = connection.send_command("show ntp status")
        assoc_out = connection.send_command("show ntp associations")
    except Exception as exc:
        results["issues"].append(f"Command execution failed: {exc}")
        return results

    status = parse_ntp_status(status_out)
    results.update({
        "synchronized": status["synchronized"],
        "stratum": status["stratum"],
        "offset_ms": status["offset"],
        "reference": status["reference"],
        "peer_count": parse_ntp_peer_count(assoc_out),
    })

    if not status["synchronized"]:
        results["issues"].append("NTP clock is NOT synchronized")

    if status["stratum"] is not None and status["stratum"] > max_stratum:
        results["issues"].append(
            f"Stratum {status['stratum']} exceeds threshold of {max_stratum}"
        )

    if status["offset"] is not None and abs(status["offset"]) > max_offset_ms:
        results["issues"].append(
            f"Clock offset {status['offset']} ms exceeds ±{max_offset_ms} ms threshold"
        )

    if results["peer_count"] == 0:
        results["issues"].append("No NTP peer associations found")

    return results


def print_report(host, results):
    sep = "-" * 52
    print(sep)
    print(f"NTP Sync Report: {host}")
    print(sep)
    print(f"  Synchronized : {'YES' if results['synchronized'] else 'NO'}")
    print(f"  Stratum      : {results['stratum'] if results['stratum'] is not None else 'unknown'}")
    print(f"  Offset (ms)  : {results['offset_ms'] if results['offset_ms'] is not None else 'unknown'}")
    print(f"  Reference    : {results['reference'] or 'unknown'}")
    print(f"  Peer count   : {results['peer_count']}")

    if results["issues"]:
        print(f"\n  ISSUES ({len(results['issues'])}):")
        for issue in results["issues"]:
            print(f"    [!] {issue}")
        print("\nResult: FAIL")
    else:
        print("\nResult: PASS")
    print(sep)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Validate NTP synchronization health on a network device"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", default=None,
                        help="SSH password (prompted if omitted)")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=["cisco_ios", "cisco_xe", "cisco_nxos"],
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--max-stratum", type=int, default=5,
        help="Maximum acceptable NTP stratum level (default: 5)",
    )
    parser.add_argument(
        "--max-offset", type=float, default=100.0,
        help="Maximum acceptable clock offset in milliseconds (default: 100.0)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser


def main():
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}@{args.device}: ")

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": password,
        "port": args.port,
        "timeout": 30,
    }

    logger.info("Connecting to %s", args.device)

    try:
        with ConnectHandler(**device_params) as conn:
            logger.info("Connected; running NTP checks")
            results = run_ntp_checks(conn, args.max_stratum, args.max_offset)
    except AuthenticationException:
        print(f"ERROR: Authentication failed for {args.username}@{args.device}", file=sys.stderr)
        sys.exit(1)
    except NetmikoTimeoutException:
        print(f"ERROR: Connection timed out to {args.device}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print_report(args.device, results)
    sys.exit(2 if results["issues"] else 0)


if __name__ == "__main__":
    main()
```