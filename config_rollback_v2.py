config_commit_confirm.py - Commit-confirm with auto-rollback for network devices.

Applies configuration changes and starts a countdown timer. If the operator
does not confirm within the timeout window, the original configuration is
automatically restored. Mirrors the commit-confirmed / rollback-on-timeout
pattern found in Junos and IOS-XR, implemented in software for IOS/IOS-XE.

Usage:
    python config_commit_confirm.py -d 192.168.1.1 -u admin -p secret \
        -c changes.txt --timeout 120

    # Preview without connecting:
    python config_commit_confirm.py -d 192.168.1.1 -u admin -p secret \
        -c changes.txt --dry-run

Prerequisites:
    pip install netmiko
    Config file: one IOS command per line, blank lines and ! comments ignored.
"""

import argparse
import logging
import select
import sys
import time
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def capture_running_config(conn):
    log.info("Capturing current running configuration")
    output = conn.send_command("show running-config", read_timeout=60)
    if not output or "Invalid input" in output:
        raise RuntimeError("Failed to capture running configuration")
    return output


def apply_config(conn, config_lines):
    log.info("Applying %d configuration line(s)", len(config_lines))
    return conn.send_config_set(config_lines, read_timeout=30)


def restore_config(conn, saved_config):
    """Push saved config lines back to the device and write memory."""
    log.warning("Restoring original configuration")
    lines = []
    for line in saved_config.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("!"):
            continue
        if stripped.startswith("Building configuration") or stripped.startswith("Current configuration"):
            continue
        lines.append(line.rstrip())
    conn.send_config_set(lines, read_timeout=120)
    conn.save_config()
    log.info("Rollback complete — original configuration saved")


def wait_for_confirm(timeout_seconds):
    """
    Block up to timeout_seconds waiting for operator to type 'confirm'.
    Returns True if confirmed, False on timeout.
    Uses select() for non-blocking stdin (Linux/macOS only).
    """
    deadline = time.time() + timeout_seconds
    print(
        f"\n[COMMIT-CONFIRM] Changes applied. You have {timeout_seconds}s to confirm.\n"
        "  Type 'confirm' and press Enter to keep changes, or wait for auto-rollback.\n"
    )
    while time.time() < deadline:
        remaining = int(deadline - time.time())
        print(f"\r  Auto-rollback in {remaining:3d}s  |  type 'confirm' to keep: ", end="", flush=True)
        ready, _, _ = select.select([sys.stdin], [], [], 1.0)
        if ready:
            user_input = sys.stdin.readline().strip().lower()
            if user_input == "confirm":
                print()
                return True
    print("\n  Timeout expired — rolling back.")
    return False


def load_config_file(path):
    lines = []
    for line in Path(path).read_text().splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("!"):
            lines.append(line.rstrip())
    return lines


def build_connection_params(args):
    params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }
    if args.secret:
        params["secret"] = args.secret
    return params


def parse_args():
    parser = argparse.ArgumentParser(
        description="Apply config with auto-rollback if operator does not confirm in time."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("-c", "--config-file", required=True, help="File with IOS commands to apply")
    parser.add_argument("--secret", default=None, help="Enable secret")
    parser.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)"
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--timeout", type=int, default=60,
        help="Seconds before auto-rollback triggers (default: 60)"
    )
    parser.add_argument("--no-save", action="store_true", help="Skip write mem after confirming")
    parser.add_argument("--dry-run", action="store_true", help="Print commands and exit without connecting")
    return parser.parse_args()


def main():
    args = parse_args()

    config_path = Path(args.config_file)
    if not config_path.exists():
        log.error("Config file not found: %s", config_path)
        sys.exit(1)

    config_lines = load_config_file(config_path)
    if not config_lines:
        log.error("Config file is empty or contains only comments")
        sys.exit(1)

    if args.dry_run:
        print(f"DRY RUN — {len(config_lines)} line(s) to apply to {args.device}:")
        for line in config_lines:
            print(f"  {line}")
        sys.exit(0)

    try:
        log.info("Connecting to %s (%s)", args.device, args.device_type)
        with ConnectHandler(**build_connection_params(args)) as conn:
            if args.secret:
                conn.enable()

            original_config = capture_running_config(conn)
            apply_config(conn, config_lines)

            confirmed = wait_for_confirm(args.timeout)

            if confirmed:
                if not args.no_save:
                    conn.save_config()
                    log.info("Configuration saved")
                log.info("Change confirmed and committed")
                print("\nSuccess: changes committed.")
            else:
                restore_config(conn, original_config)
                print("\nRollback complete. Device restored to pre-change state.")
                sys.exit(2)

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.device)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted — manual rollback may be required.")
        sys.exit(130)
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()