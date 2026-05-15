#!/usr/bin/env python3
"""
Device Configuration Auditor - Validates device configurations against compliance baselines.

Purpose:
    Connects to network devices and audits their running configuration against
    a compliance baseline. Reports configuration deviations, missing configs,
    and policy violations for security and compliance assessment.

Usage:
    python device_config_auditor.py -d 192.168.1.1 -u admin -p password \
        -t cisco_ios -b baseline.json -o report.json

Prerequisites:
    - netmiko library installed (pip install netmiko)
    - Device reachable and credentials valid
    - Baseline JSON file with compliance rules
    - SSH access enabled on target device

Baseline JSON example:
    {
        "required_lines": ["ip domain-name example.com", "logging 192.168.1.100"],
        "forbidden_lines": ["enable password", "no logging"],
        "required_services": ["logging", "snmp"],
        "forbidden_services": ["service udp-small-servers"],
        "min_config_length": 1000
    }
"""

import argparse
import json
import logging
import sys
from typing import Dict, List, Tuple

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_baseline(baseline_file: str) -> Dict:
    """Load compliance baseline from JSON file."""
    try:
        with open(baseline_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"Baseline file not found: {baseline_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in baseline: {e}")
        sys.exit(1)


def connect_device(device_params: Dict) -> ConnectHandler:
    """Establish SSH connection to network device."""
    try:
        logger.info(f"Connecting to {device_params['host']}...")
        device = ConnectHandler(**device_params)
        logger.info("Connection established")
        return device
    except NetmikoAuthenticationException:
        logger.error("Authentication failed - check credentials")
        sys.exit(1)
    except NetmikoTimeoutException:
        logger.error("Connection timeout - device unreachable")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Connection error: {e}")
        sys.exit(1)


def get_running_config(device: ConnectHandler) -> str:
    """Retrieve running configuration from device."""
    try:
        config = device.send_command("show running-config")
        logger.info(f"Retrieved {len(config)} bytes of configuration")
        return config
    except Exception as e:
        logger.error(f"Failed to retrieve running config: {e}")
        sys.exit(1)


def check_required_lines(config: str, required_lines: List[str]) -> Tuple[List[str], List[str]]:
    """Validate required configuration lines are present."""
    found = []
    missing = []

    for line in required_lines:
        if line in config:
            found.append(line)
            logger.info(f"✓ Found required: {line}")
        else:
            missing.append(line)
            logger.warning(f"✗ Missing required: {line}")

    return found, missing


def check_forbidden_lines(config: str, forbidden_lines: List[str]) -> Tuple[List[str], List[str]]:
    """Validate forbidden configuration lines are absent."""
    compliant = []
    violations = []

    for line in forbidden_lines:
        if line not in config:
            compliant.append(line)
            logger.info(f"✓ Forbidden absent: {line}")
        else:
            violations.append(line)
            logger.warning(f"✗ Found forbidden: {line}")

    return compliant, violations


def check_services(config: str, required: List[str], forbidden: List[str]) -> Dict[str, bool]:
    """Validate required and forbidden services."""
    results = {"required_present": {}, "forbidden_absent": {}}

    for service in required:
        present = service in config
        results["required_present"][service] = present
        status = "✓" if present else "✗"
        logger.info(f"{status} Service '{service}': {present}")

    for service in forbidden:
        absent = service not in config
        results["forbidden_absent"][service] = absent
        status = "✓" if absent else "✗"
        logger.info(f"{status} Service '{service}' absent: {absent}")

    return results


def audit_configuration(baseline: Dict, config: str) -> Dict:
    """Perform complete configuration audit against baseline."""
    report = {
        "compliance_status": "PASS",
        "violations": [],
        "summary": {}
    }

    # Check configuration length minimum
    if "min_config_length" in baseline:
        min_length = baseline["min_config_length"]
        if len(config) < min_length:
            report["compliance_status"] = "FAIL"
            report["violations"].append(
                f"Config length {len(config)} bytes is below minimum {min_length}"
            )
            logger.warning(f"Config length check failed: {len(config)} < {min_length}")

    # Validate required lines
    if "required_lines" in baseline:
        found, missing = check_required_lines(config, baseline["required_lines"])
        report["summary"]["required_lines"] = {"found": len(found), "missing": len(missing)}
        if missing:
            report["compliance_status"] = "FAIL"
            report["violations"].extend([f"Missing required: {line}" for line in missing])

    # Validate forbidden lines
    if "forbidden_lines" in baseline:
        compliant, violations = check_forbidden_lines(config, baseline["forbidden_lines"])
        report["summary"]["forbidden_lines"] = {"compliant": len(compliant), "violations": len(violations)}
        if violations:
            report["compliance_status"] = "FAIL"
            report["violations"].extend([f"Forbidden found: {line}" for line in violations])

    # Validate services
    if "required_services" in baseline or "forbidden_services" in baseline:
        services_result = check_services(
            config,
            baseline.get("required_services", []),
            baseline.get("forbidden_services", [])
        )
        report["summary"]["services"] = services_result

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Audit network device configuration against compliance baseline"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("-t", "--device-type", required=True, help="Device type (e.g., cisco_ios)")
    parser.add_argument("-b", "--baseline", required=True, help="Baseline JSON file path")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--timeout", type=int, default=30, help="Connection timeout in seconds")
    parser.add_argument("-o", "--output", help="Save report to JSON file")

    args = parser.parse_args()

    # Load and validate baseline
    baseline = load_baseline(args.baseline)
    logger.info(f"Baseline loaded: {args.baseline}")

    # Connect to device
    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "timeout": args.timeout,
    }

    device = connect_device(device_params)

    try:
        # Retrieve and audit configuration
        config = get_running_config(device)
        report = audit_configuration(baseline, config)

        # Display results
        logger.info(f"\nAudit Result: {report['compliance_status']}")
        logger.info(f"Violations: {len(report['violations'])}")

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report saved: {args.output}")

        sys.exit(0 if report["compliance_status"] == "PASS" else 1)

    finally:
        device.disconnect()
        logger.info("Disconnected")


if __name__ == "__main__":
    main()