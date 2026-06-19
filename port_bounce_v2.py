batch_port_bounce.py - Bounce multiple interfaces with pre/post state capture.

Purpose:
    Perform a bulk interface shutdown/no-shutdown cycle across one or more
    Cisco IOS ports, capturing interface status, error counters, and CDP
    neighbor state before and after each bounce to validate recovery.
    Results are written as a structured JSON report.

Usage:
    python batch_port_bounce.py \
        --host 10.0.0.1 --username admin --password secret \
        --interfaces GigabitEthernet0/1,GigabitEthernet0/2 \
        --hold-time 5 --recovery-timeout 60 --output report.json

    # Capture state only (no actual bounce):
    python batch_port_bounce.py --host 10.0.0.1 -u admin -p secret \
        --interfaces Gi0/1 --dry-run

Prerequisites:
    pip install netmiko
    Tested against Cisco IOS/IOS-XE. Commands used:
        show ip interface brief interface <intf>
        show interfaces <intf>
        show cdp neighbors <intf> detail
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_link_state(brief_output: str) -> tuple:
    """Return (status, protocol) from 'show ip interface brief' output."""
    for line in brief_output.splitlines():
        parts = line.split()
        if len(parts) >= 6 and not line.strip().lower().startswith("interface"):
            return parts[4], parts[5]
    return "unknown", "unknown"


def parse_error_counters(intf_output: str) -> dict:
    """Extract input/output error counts from 'show interfaces' output."""
    in_errors = out_errors = 0
    for line in intf_output.splitlines():
        stripped = line.strip().lower()
        if "input errors" in stripped:
            try:
                in_errors = int(stripped.split()[0])
            except (ValueError, IndexError):
                pass
        elif "output errors" in stripped:
            try:
                out_errors = int(stripped.split()[0])
            except (ValueError, IndexError):
                pass
    return {"input_errors": in_errors, "output_errors": out_errors}


def get_interface_state(conn, interface: str) -> dict:
    """Collect status, error counters, and CDP neighbor count for one interface."""
    brief = conn.send_command(f"show ip interface brief interface {interface}")
    status, protocol = parse_link_state(brief)

    intf_detail = conn.send_command(f"show interfaces {interface}")
    errors = parse_error_counters(intf_detail)

    cdp_out = conn.send_command(f"show cdp neighbors {interface} detail")
    cdp_neighbors = cdp_out.count("Device ID:")

    return {
        "status": status,
        "protocol": protocol,
        "cdp_neighbors": cdp_neighbors,
        "timestamp": _utcnow(),
        **errors,
    }


def wait_for_link_up(conn, interface: str, timeout: int) -> bool:
    """Poll until interface protocol is 'up' or timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        brief = conn.send_command(f"show ip interface brief interface {interface}")
        _, protocol = parse_link_state(brief)
        if protocol == "up":
            return True
        time.sleep(3)
    return False


def bounce_interface(conn, interface: str, hold_time: int, recovery_timeout: int) -> dict:
    """Shut down an interface, pause, re-enable, then wait for recovery."""
    log.info("  shutdown %s (holding %ds)", interface, hold_time)
    conn.send_config_set([f"interface {interface}", "shutdown"])
    time.sleep(hold_time)

    log.info("  no shutdown %s (recovery timeout %ds)", interface, recovery_timeout)
    conn.send_config_set([f"interface {interface}", "no shutdown"])

    recovered = wait_for_link_up(conn, interface, recovery_timeout)
    if not recovered:
        log.warning("  %s did not come back up within %ds", interface, recovery_timeout)

    return {
        "hold_time_sec": hold_time,
        "recovery_timeout_sec": recovery_timeout,
        "recovered": recovered,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Batch port bounce with pre/post state capture and JSON report"
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--username", "-u", required=True)
    parser.add_argument("--password", "-p", required=True)
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument(
        "--interfaces",
        required=True,
        help="Comma-separated interface names, e.g. Gi0/1,Gi0/2",
    )
    parser.add_argument(
        "--hold-time",
        type=int,
        default=5,
        metavar="SECS",
        help="Seconds to hold the port down before re-enabling (default: 5)",
    )
    parser.add_argument(
        "--recovery-timeout",
        type=int,
        default=60,
        metavar="SECS",
        help="Seconds to wait for link to recover after re-enable (default: 60)",
    )
    parser.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="Write JSON report to FILE (default: stdout)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Capture interface state only; skip the actual bounce",
    )
    args = parser.parse_args()

    interfaces = [i.strip() for i in args.interfaces.split(",") if i.strip()]
    if not interfaces:
        log.error("No interfaces provided via --interfaces")
        sys.exit(1)

    try:
        log.info("Connecting to %s", args.host)
        conn = ConnectHandler(
            device_type=args.device_type,
            host=args.host,
            username=args.username,
            password=args.password,
        )
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        sys.exit(1)

    results = []
    try:
        for intf in interfaces:
            log.info("Processing %s", intf)
            entry = {"interface": intf, "pre": get_interface_state(conn, intf)}

            if args.dry_run:
                log.info("  dry-run: skipping bounce")
            else:
                entry["bounce"] = bounce_interface(
                    conn, intf, args.hold_time, args.recovery_timeout
                )
                entry["post"] = get_interface_state(conn, intf)
                outcome = "recovered" if entry["bounce"]["recovered"] else "FAILED"
                log.info("  %s: %s", intf, outcome)

            results.append(entry)
    finally:
        conn.disconnect()

    bounced = len(results) if not args.dry_run else 0
    recovered_count = sum(
        1 for r in results if r.get("bounce", {}).get("recovered", False)
    )

    report = {
        "host": args.host,
        "generated_at": _utcnow(),
        "dry_run": args.dry_run,
        "summary": {
            "total_interfaces": len(results),
            "bounced": bounced,
            "recovered": recovered_count,
            "failed_recovery": bounced - recovered_count,
        },
        "interfaces": results,
    }

    payload = json.dumps(report, indent=2)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(payload)
        log.info("Report written to %s", args.output)
    else:
        print(payload)

    sys.exit(1 if report["summary"]["failed_recovery"] else 0)


if __name__ == "__main__":
    main()