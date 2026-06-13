```python
#!/usr/bin/env python3
"""
config_compliance_audit.py - Network device configuration compliance auditor.

Connects to a network device, retrieves the running configuration, and validates
it against compliance rules defined in a JSON file. Produces a scored pass/fail
report useful for audits, change controls, and security baselines.

Usage:
    python config_compliance_audit.py --host 192.168.1.1 --username admin \
        --password secret --device-type cisco_ios --rules rules.json

    python config_compliance_audit.py --host 10.0.0.1 --username admin \
        --password secret --rules rules.json --output report.txt --verbose

Prerequisites:
    pip install netmiko

Rules file format (JSON):
    {
        "rules": [
            {
                "name": "NTP server configured",
                "required": ["ntp server 10.0.0.1"],
                "severity": "high"
            },
            {
                "name": "SSH version 2 enforced",
                "required": ["ip ssh version 2"],
                "severity": "critical"
            },
            {
                "name": "Telnet transport disabled",
                "forbidden": ["transport input telnet"],
                "severity": "critical"
            }
        ]
    }
"""

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class RuleResult:
    name: str
    severity: str
    passed: bool
    findings: list = field(default_factory=list)


def load_rules(rules_file):
    try:
        with open(rules_file) as f:
            data = json.load(f)
        rules = data.get("rules", [])
        if not rules:
            logger.error("No rules found in %s", rules_file)
            sys.exit(1)
        return rules
    except FileNotFoundError:
        logger.error("Rules file not found: %s", rules_file)
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in rules file: %s", e)
        sys.exit(1)


def fetch_config(conn, enable_secret):
    if enable_secret:
        conn.enable()
    logger.info("Fetching running configuration...")
    return conn.send_command("show running-config", read_timeout=60)


def evaluate_rule(rule, config_lower):
    name = rule.get("name", "Unnamed")
    severity = rule.get("severity", "medium")
    findings = []

    for pattern in rule.get("required", []):
        if pattern.lower() not in config_lower:
            findings.append(f"MISSING required: '{pattern}'")

    for pattern in rule.get("forbidden", []):
        if pattern.lower() in config_lower:
            findings.append(f"FOUND forbidden: '{pattern}'")

    return RuleResult(name=name, severity=severity, passed=not findings, findings=findings)


def print_report(results, host, output_file=None):
    total = len(results)
    passed_count = sum(1 for r in results if r.passed)
    failed_count = total - passed_count
    score = int((passed_count / total) * 100) if total else 0

    lines = [
        "",
        "=" * 64,
        f"Compliance Report — {host}",
        "=" * 64,
        f"Rules: {total}   Passed: {passed_count}   Failed: {failed_count}   Score: {score}%",
        "=" * 64,
        "",
    ]

    sorted_results = sorted(
        results, key=lambda r: (r.passed, SEVERITY_ORDER.get(r.severity, 9))
    )
    for result in sorted_results:
        status = "PASS" if result.passed else "FAIL"
        sev = result.severity.upper().ljust(8)
        lines.append(f"[{status}] [{sev}] {result.name}")
        for finding in result.findings:
            lines.append(f"         {finding}")

    lines += ["", "=" * 64, ""]
    report = "\n".join(lines)
    print(report)

    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(report)
            logger.info("Report saved to %s", output_file)
        except OSError as e:
            logger.warning("Could not write output file: %s", e)

    return 0 if failed_count == 0 else 1


def parse_args():
    parser = argparse.ArgumentParser(
        description="Audit device running-config against JSON compliance rules"
    )
    parser.add_argument("--host", required=True, help="Device hostname or IP address")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--rules", required=True, help="Path to JSON compliance rules file")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--secret", default="", help="Enable mode secret")
    parser.add_argument("--output", help="Write report to this file in addition to stdout")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    rules = load_rules(args.rules)
    logger.info("Loaded %d compliance rules from %s", len(rules), args.rules)

    device_params = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "secret": args.secret,
    }

    try:
        logger.info("Connecting to %s (%s)...", args.host, args.device_type)
        with ConnectHandler(**device_params) as conn:
            config = fetch_config(conn, args.secret)
    except AuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except NetmikoTimeoutException:
        logger.error("Connection timed out for %s", args.host)
        return 1
    except Exception as e:
        logger.error("Connection error: %s", e)
        return 1

    config_lower = config.lower()
    results = [evaluate_rule(rule, config_lower) for rule in rules]
    return print_report(results, args.host, output_file=args.output)


if __name__ == "__main__":
    sys.exit(main())
```