acl_validator.py - Post-change ACL compliance checker for Cisco IOS/IOS-XE.

Purpose:
    Connects to a network device via SSH and verifies that specified ACL entries
    are present in the named access list. Designed for post-change validation
    during change windows to confirm ACL edits were applied correctly.

Usage:
    python acl_validator.py --host 192.168.1.1 -u admin -p secret \
        --acl MGMT-ACCESS --rules rules.json

    python acl_validator.py --host 10.0.0.1 -u netops \
        --acl WAN-FILTER \
        --check-entry "permit tcp 10.0.0.0 0.0.0.255 any eq 443" \
        --check-entry "deny ip any any log" \
        --output results.json

Prerequisites:
    pip install netmiko
    Cisco IOS / IOS-XE device reachable via SSH

Rules file format (rules.json):
    ["permit tcp 10.1.0.0 0.0.0.255 any eq 443", "deny ip any any log"]

    Each string is matched as a case-insensitive substring against ACL output.
    Exit code 0 = all entries present; 1 = one or more missing.
"""

import argparse
import json
import logging
import sys
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def fetch_acl(connection, acl_name):
    output = connection.send_command(f"show ip access-lists {acl_name}")
    if "does not exist" in output or "Invalid input" in output:
        return None, output.strip()
    return output, None


def validate_entries(acl_output, expected_entries):
    lines = [line.strip().lower() for line in acl_output.splitlines() if line.strip()]
    results = []
    for entry in expected_entries:
        matched = any(entry.lower().strip() in line for line in lines)
        results.append({
            "entry": entry,
            "present": matched,
            "status": "PASS" if matched else "FAIL",
        })
    return results


def build_parser():
    parser = argparse.ArgumentParser(
        description="Validate ACL entries on a Cisco IOS/IOS-XE device."
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--username", "-u", required=True, help="SSH username")
    parser.add_argument(
        "--password", "-p", default=None, help="SSH password (prompted if omitted)"
    )
    parser.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)"
    )
    parser.add_argument("--acl", required=True, help="ACL name to inspect")
    parser.add_argument(
        "--rules", metavar="FILE",
        help="JSON file with list of expected ACL entry substrings"
    )
    parser.add_argument(
        "--check-entry", metavar="ENTRY", action="append", dest="inline_entries",
        help="Expected ACL entry substring (repeatable; combined with --rules)"
    )
    parser.add_argument(
        "--output", metavar="FILE", help="Write JSON results to this file"
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}@{args.host}: ")

    expected = list(args.inline_entries or [])
    if args.rules:
        try:
            with open(args.rules) as fh:
                file_rules = json.load(fh)
            if not isinstance(file_rules, list):
                log.error("Rules file must contain a JSON array of strings.")
                sys.exit(1)
            expected.extend(file_rules)
        except (OSError, json.JSONDecodeError) as exc:
            log.error("Failed to load rules file: %s", exc)
            sys.exit(1)

    if not expected:
        log.error("No entries to validate. Use --rules or --check-entry.")
        sys.exit(1)

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": password,
    }

    log.info("Connecting to %s ...", args.host)
    try:
        with ConnectHandler(**device) as conn:
            log.info("Fetching ACL '%s' ...", args.acl)
            acl_output, error = fetch_acl(conn, args.acl)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection to %s timed out.", args.host)
        sys.exit(1)

    if error:
        log.error("ACL '%s' not found on %s:\n%s", args.acl, args.host, error)
        sys.exit(1)

    if args.verbose:
        log.debug("Raw ACL output:\n%s", acl_output)

    results = validate_entries(acl_output, expected)
    passed = sum(1 for r in results if r["present"])
    failed = len(results) - passed

    print(f"\nACL Validation: {args.acl}  |  Host: {args.host}")
    print("-" * 62)
    for r in results:
        symbol = "+" if r["present"] else "-"
        print(f"  [{symbol}] {r['status']:4s}  {r['entry']}")
    print("-" * 62)
    print(f"  Total: {len(results)}   Passed: {passed}   Failed: {failed}\n")

    if args.output:
        payload = {
            "host": args.host,
            "acl": args.acl,
            "passed": passed,
            "failed": failed,
            "results": results,
        }
        try:
            with open(args.output, "w") as fh:
                json.dump(payload, fh, indent=2)
            log.info("Results saved to %s", args.output)
        except OSError as exc:
            log.warning("Could not write output file: %s", exc)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()