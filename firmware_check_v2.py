The user has fully specified all requirements and explicitly said to output only the script content — no design exploration needed. Proceeding directly.

"""
firmware_compliance_audit.py — Multi-device firmware compliance auditor.

Reads a YAML inventory of devices with their expected firmware versions, connects
to each device via netmiko, retrieves the running version, and produces a
pass/fail compliance report. Exits non-zero if any device is non-compliant.

Usage:
    python firmware_compliance_audit.py \
        --inventory devices.yaml \
        --username admin \
        --password secret \
        [--secret enable_pw] \
        [--output report.json] \
        [--timeout 30] \
        [--verbose]

Prerequisites:
    pip install netmiko pyyaml

Inventory YAML format:
    devices:
      - host: 192.168.1.1
        device_type: cisco_ios
        expected_version: "15.9(3)M5"
      - host: 192.168.1.2
        device_type: cisco_nxos
        expected_version: "9.3(9)"
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone

import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

VERSION_COMMANDS = {
    "cisco_ios": "show version",
    "cisco_nxos": "show version",
    "cisco_asa": "show version",
    "juniper_junos": "show version",
    "arista_eos": "show version",
    "hp_comware": "display version",
}

VERSION_MARKERS = {
    "cisco_ios": "Version ",
    "cisco_nxos": "NXOS: version",
    "cisco_asa": "Software Version",
    "juniper_junos": "Junos:",
    "arista_eos": "EOS version:",
    "hp_comware": "Version",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit firmware compliance across a device inventory."
    )
    parser.add_argument("--inventory", required=True, help="Path to YAML inventory file")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument("--secret", default="", help="Enable secret (if required)")
    parser.add_argument("--output", help="Write JSON report to this file path")
    parser.add_argument(
        "--timeout", type=int, default=30, help="SSH connection timeout in seconds"
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.DEBUG if verbose else logging.INFO,
        stream=sys.stderr,
    )
    logging.getLogger("paramiko").setLevel(logging.WARNING)


def load_inventory(path: str) -> list:
    with open(path) as f:
        data = yaml.safe_load(f)
    devices = data.get("devices", [])
    if not devices:
        logging.error("Inventory file contains no devices: %s", path)
        sys.exit(1)
    return devices


def extract_version(output: str, device_type: str) -> str:
    marker = VERSION_MARKERS.get(device_type, "Version")
    for line in output.splitlines():
        if marker.lower() in line.lower():
            tokens = line.split()
            for i, token in enumerate(tokens):
                if token.rstrip(",").lower() in ("version", "ver"):
                    if i + 1 < len(tokens):
                        return tokens[i + 1].strip(",").rstrip(".")
    return "UNKNOWN"


def audit_device(
    device: dict, username: str, password: str, secret: str, timeout: int
) -> dict:
    host = device["host"]
    device_type = device.get("device_type", "cisco_ios")
    expected = device.get("expected_version", "")
    result = {
        "host": host,
        "device_type": device_type,
        "expected_version": expected,
        "running_version": None,
        "compliant": False,
        "error": None,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    cmd = VERSION_COMMANDS.get(device_type)
    if not cmd:
        result["error"] = f"Unsupported device_type: {device_type}"
        logging.warning("[%s] %s", host, result["error"])
        return result

    try:
        logging.info("[%s] Connecting (%s)...", host, device_type)
        with ConnectHandler(
            device_type=device_type,
            host=host,
            username=username,
            password=password,
            secret=secret or password,
            timeout=timeout,
        ) as conn:
            output = conn.send_command(cmd)

        version = extract_version(output, device_type)
        result["running_version"] = version
        result["compliant"] = version == expected
        status = "PASS" if result["compliant"] else "FAIL"
        logging.info(
            "[%s] %s — running=%s expected=%s", host, status, version, expected
        )

    except NetmikoAuthenticationException:
        result["error"] = "Authentication failed"
        logging.error("[%s] Authentication failed", host)
    except NetmikoTimeoutException:
        result["error"] = "Connection timed out"
        logging.error("[%s] Connection timed out", host)
    except Exception as exc:
        result["error"] = str(exc)
        logging.error("[%s] %s", host, exc)

    return result


def print_report(results: list) -> None:
    total = len(results)
    passed = sum(1 for r in results if r["compliant"])
    errors = sum(1 for r in results if r["error"])
    width = 60

    print(f"\n{'=' * width}")
    print("  FIRMWARE COMPLIANCE REPORT")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'=' * width}")
    print(f"  Devices checked : {total}")
    print(f"  Compliant       : {passed}")
    print(f"  Non-compliant   : {total - passed - errors}")
    print(f"  Errors          : {errors}")
    print(f"{'=' * width}")

    for r in results:
        if r["error"]:
            tag = "ERROR"
            detail = r["error"]
        elif r["compliant"]:
            tag = "PASS "
            detail = f"running={r['running_version']}"
        else:
            tag = "FAIL "
            detail = f"running={r['running_version']}  expected={r['expected_version']}"
        print(f"  [{tag}]  {r['host']:<20} {detail}")

    print()


if __name__ == "__main__":
    args = parse_args()
    configure_logging(args.verbose)

    inventory = load_inventory(args.inventory)
    results = [
        audit_device(d, args.username, args.password, args.secret, args.timeout)
        for d in inventory
    ]

    print_report(results)

    if args.output:
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "results": results,
        }
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        logging.info("JSON report written to %s", args.output)

    non_compliant = [r for r in results if not r["compliant"]]
    sys.exit(1 if non_compliant else 0)