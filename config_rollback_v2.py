```python
"""
Failsafe Config Deploy with Auto-Rollback

Pushes a configuration change to a network device and waits for operator
confirmation within a configurable window. If confirmation is not received
before the deadline (or is explicitly declined), the device is automatically
restored to its pre-change running configuration.

This implements the "commit confirmed" pattern common in production change
management: changes go live immediately, but auto-revert unless an operator
actively approves them — useful when SSH access itself might be disrupted by
the change.

Usage:
    python config_rollback_v3.py -d 192.168.1.1 -u admin -p secret \\
        -t cisco_ios --config-file changes.txt --confirm-timeout 90

    python config_rollback_v3.py -d 10.0.0.1 -u admin -p secret \\
        --config-file acl_update.txt --dry-run

Prerequisites:
    pip install netmiko
    SSH access to target device with sufficient privilege to apply config.
"""

import argparse
import logging
import sys
import time

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def capture_running_config(conn):
    log.info("Capturing pre-change running configuration")
    output = conn.send_command("show running-config")
    if not output:
        raise RuntimeError("Empty response from 'show running-config'")
    return output


def load_config_lines(config_file):
    with open(config_file) as fh:
        lines = [
            line.rstrip()
            for line in fh
            if line.strip() and not line.lstrip().startswith("!")
        ]
    if not lines:
        raise ValueError(f"No config lines found in {config_file}")
    return lines


def apply_config(conn, lines):
    log.info("Applying %d config line(s)", len(lines))
    return conn.send_config_set(lines)


def rollback_to_checkpoint(conn, checkpoint):
    log.warning("Rolling back to pre-change configuration")
    lines = [
        line
        for line in checkpoint.splitlines()
        if line.strip()
        and not line.startswith("!")
        and not line.startswith("Building configuration")
        and not line.startswith("Current configuration")
    ]
    conn.send_config_set(lines)
    log.info("Rollback applied")


def wait_for_confirmation(timeout_seconds):
    """Prompt operator to confirm within the window. Returns True if confirmed."""
    deadline = time.monotonic() + timeout_seconds
    print(f"\n*** Change is live. Confirm to keep, or it auto-reverts in {timeout_seconds}s ***")
    while time.monotonic() < deadline:
        remaining = max(0, int(deadline - time.monotonic()))
        try:
            answer = input(f"  [{remaining:3d}s] Confirm change? (yes/no): ").strip().lower()
        except EOFError:
            return False
        if answer in ("yes", "y"):
            return True
        if answer in ("no", "n"):
            log.info("Operator declined — initiating rollback")
            return False
        print("  Please enter 'yes' or 'no'.")
    log.warning("Confirmation window expired — initiating rollback")
    return False


def parse_args():
    parser = argparse.ArgumentParser(
        description="Deploy config with automatic rollback if not confirmed"
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument(
        "-t", "--device-type",
        default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--enable-secret", help="Enable mode secret (if required)")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--config-file", required=True, help="File of config lines to push")
    parser.add_argument(
        "--confirm-timeout", type=int, default=60,
        help="Seconds before auto-rollback (default: 60, min: 10)",
    )
    parser.add_argument("--session-log", help="Write raw session transcript to this file")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print config lines and exit without connecting",
    )
    args = parser.parse_args()
    if args.confirm_timeout < 10:
        parser.error("--confirm-timeout must be at least 10 seconds")
    return args


def main():
    args = parse_args()

    if args.dry_run:
        lines = load_config_lines(args.config_file)
        print(f"DRY RUN — {len(lines)} line(s) would be applied to {args.device}:")
        for line in lines:
            print(f"  {line}")
        sys.exit(0)

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "secret": args.enable_secret or args.password,
        "port": args.port,
        "timeout": 30,
        "session_log": args.session_log or None,
    }

    try:
        lines = load_config_lines(args.config_file)
    except (FileNotFoundError, ValueError) as exc:
        log.error("%s", exc)
        sys.exit(1)

    try:
        log.info("Connecting to %s (%s)", args.device, args.device_type)
        with ConnectHandler(**device_params) as conn:
            if args.enable_secret:
                conn.enable()

            checkpoint = capture_running_config(conn)
            apply_config(conn, lines)

            confirmed = wait_for_confirmation(args.confirm_timeout)

            if confirmed:
                log.info("Change confirmed — saving configuration on %s", args.device)
                conn.save_config()
                log.info("Done")
            else:
                rollback_to_checkpoint(conn, checkpoint)
                conn.save_config()
                log.info("Device restored to pre-change state on %s", args.device)
                sys.exit(2)

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.device)
        sys.exit(1)
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
```