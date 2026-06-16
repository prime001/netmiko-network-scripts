```python
"""
config_compliance.py — Configuration compliance auditor for network devices.

Connects to a device via netmiko, pulls the running configuration, and checks
it against a set of user-defined compliance rules (regex-based). Each rule
reports PASS or FAIL with optional remediation hints.

Usage:
    python config_compliance.py -d 192.168.1.1 -u admin -p secret \
        --device-type cisco_ios --rules-file compliance_rules.json

    python config_compliance.py -d 192.168.1.1 -u admin -p secret \
        --device-type cisco_ios --builtin-rules cis_ios

Prerequisites:
    pip install netmiko
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

BUILTIN_RULESETS = {
    "cis_ios": [
        {"name": "SSH version 2", "pattern": r"ip ssh version 2", "required": True,
         "hint": "Add: ip ssh version 2"},
        {"name": "Password encryption", "pattern": r"service password-encryption", "required": True,
         "hint": "Add: service password-encryption"},
        {"name": "No Telnet on VTY", "pattern": r"transport input telnet\b", "required": False,
         "hint": "Replace 'transport input telnet' with 'transport input ssh'"},
        {"name": "Login banner", "pattern": r"banner (motd|login)", "required": True,
         "hint": "Configure a login/motd banner"},
        {"name": "No default SNMP community", "pattern": r"snmp-server community (public|private)\b",
         "required": False, "hint": "Remove default SNMP community strings"},
        {"name": "AAA new-model", "pattern": r"aaa new-model", "required": True,
         "hint": "Add: aaa new-model"},
        {"name": "Exec timeout on VTY", "pattern": r"exec-timeout [1-9]", "required": True,
         "hint": "Set exec-timeout on VTY lines (e.g. exec-timeout 10 0)"},
        {"name": "No IP source route", "pattern": r"no ip source-route", "required": True,
         "hint": "Add: no ip source-route"},
        {"name": "No IP finger", "pattern": r"no ip finger", "required": True,
         "hint": "Add: no ip finger"},
    ]
}


@dataclass
class RuleResult:
    name: str
    passed: bool
    hint: Optional[str] = None


@dataclass
class AuditReport:
    device: str
    results: list[RuleResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    def print_summary(self) -> None:
        total = len(self.results)
        print(f"\n{'='*60}")
        print(f"Compliance Report: {self.device}")
        print(f"{'='*60}")
        for r in self.results:
            status = "PASS" if r.passed else "FAIL"
            indicator = "+" if r.passed else "-"
            print(f"  [{indicator}] {status:<5}  {r.name}")
            if not r.passed and r.hint:
                print(f"          Remediation: {r.hint}")
        print(f"{'='*60}")
        print(f"  Result: {self.passed}/{total} checks passed", end="  ")
        print("COMPLIANT" if self.failed == 0 else f"NON-COMPLIANT ({self.failed} failure(s))")
        print(f"{'='*60}\n")


def load_rules(rules_file: Optional[str], builtin: Optional[str]) -> list[dict]:
    if rules_file:
        with open(rules_file) as f:
            return json.load(f)
    if builtin:
        if builtin not in BUILTIN_RULESETS:
            log.error("Unknown builtin ruleset '%s'. Available: %s", builtin, list(BUILTIN_RULESETS))
            sys.exit(1)
        return BUILTIN_RULESETS[builtin]
    log.error("Provide --rules-file or --builtin-rules")
    sys.exit(1)


def audit_config(config: str, rules: list[dict]) -> list[RuleResult]:
    results = []
    for rule in rules:
        match = bool(re.search(rule["pattern"], config, re.IGNORECASE | re.MULTILINE))
        passed = match if rule.get("required", True) else not match
        results.append(RuleResult(name=rule["name"], passed=passed, hint=rule.get("hint")))
    return results


def connect_and_audit(args) -> AuditReport:
    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "timeout": args.timeout,
    }
    if args.enable_secret:
        device_params["secret"] = args.enable_secret

    log.info("Connecting to %s (%s)", args.device, args.device_type)
    try:
        with ConnectHandler(**device_params) as conn:
            if args.enable_secret:
                conn.enable()
            log.info("Fetching running configuration...")
            config = conn.send_command("show running-config", read_timeout=60)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.device)
        sys.exit(2)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.device)
        sys.exit(3)

    rules = load_rules(args.rules_file, args.builtin_rules)
    log.info("Evaluating %d compliance rules...", len(rules))
    results = audit_config(config, rules)

    report = AuditReport(device=args.device, results=results)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit network device configuration against compliance rules."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--device-type", default="cisco_ios",
                        help="Netmiko device type (default: cisco_ios)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=15, help="Connection timeout seconds")
    parser.add_argument("--enable-secret", help="Enable mode password (if required)")
    parser.add_argument("--rules-file", help="JSON file containing compliance rules")
    parser.add_argument("--builtin-rules", choices=list(BUILTIN_RULESETS),
                        help="Use a built-in ruleset")
    parser.add_argument("--fail-on-non-compliance", action="store_true",
                        help="Exit with code 4 if any checks fail")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    report = connect_and_audit(args)
    report.print_summary()
    if args.fail_on_non_compliance and report.failed > 0:
        sys.exit(4)
```