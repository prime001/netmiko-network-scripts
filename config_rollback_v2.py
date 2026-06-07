#!/usr/bin/env python3
"""
checkpoint_rollback.py - Commit-confirmed config change with auto-revert timer.

Saves the running config as a local checkpoint before pushing any changes.
After applying the config, the script waits for explicit operator confirmation
within a configurable deadline.  If the deadline expires or the operator
declines, the pre-change checkpoint is automatically restored.

This mirrors the 'commit confirmed' workflow native to Junos/EOS, extended to
any netmiko-supported platform (Cisco IOS, NX-OS, Arista EOS, etc.).

Usage:
    python checkpoint_rollback.py -d 192.168.1.1 -u admin -p secret \
        --config changes.txt --timeout 120

    # Apply and keep without interactive prompt:
    python checkpoint_rollback.py -d 192.168.1.1 -u admin -p secret \
        --config changes.txt --yes

Prerequisites:
    pip install netmiko
"""

import argparse
import logging
import select
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

STRIP_PREFIXES = (
    "Building configuration",
    "Current configuration",
    "Last configuration change",
    "! Last",
    "!",
)


def capture_running_config(conn, device_type: str) -> str:
    log.info("Capturing pre-change running config...")
    if "junos" in device_type:
        output = conn.send_command("show configuration | display set")
    else:
        output = conn.send_command("show running-config")
    log.info("Checkpoint captured: %d bytes.", len(output))
    return output


def save_checkpoint(text: str, device: str, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe = device.replace(".", "_").replace(":", "_")
    path = out_dir / f"checkpoint_{safe}_{ts}.txt"
    path.write_text(text)
    log.info("Checkpoint written to %s", path)
    return path


def apply_config(conn, lines: list) -> str:
    log.info("Applying %d config line(s)...", len(lines))
    output = conn.send_config_set(lines)
    return output


def restore_checkpoint(conn, checkpoint: str) -> None:
    log.warning("Restoring pre-change config...")
    restore_lines = []
    for line in checkpoint.splitlines():
        stripped = line.rstrip()
        if not stripped:
            continue
        if any(stripped.startswith(p) for p in STRIP_PREFIXES):
            continue
        restore_lines.append(stripped)
    if not restore_lines:
        log.error("Checkpoint was empty — cannot restore.")
        return
    conn.send_config_set(restore_lines)
    log.info("Restore complete: sent %d lines.", len(restore_lines))


def wait_for_confirmation(timeout: int) -> bool:
    bar = "=" * 62
    print(f"\n{bar}")
    print("  CONFIG APPLIED — confirm to commit or wait to auto-revert")
    print(f"  You have {timeout}s. Type 'yes' + Enter to keep, anything else reverts.")
    print(f"{bar}\n")

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        remaining = int(deadline - time.monotonic())
        sys.stdout.write(f"\r  Confirm? ({remaining:>3}s) [yes/no]: ")
        sys.stdout.flush()
        ready, _, _ = select.select([sys.stdin], [], [], 1.0)
        if ready:
            answer = sys.stdin.readline().strip().lower()
            print()
            if answer == "yes":
                return True
            if answer:
                log.info("Operator entered '%s' — treating as decline.", answer)
                return False

    print()
    log.warning("Confirmation deadline reached — auto-reverting.")
    return False


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Commit-confirmed config change with automatic rollback on timeout.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument(
        "-t", "--device-type", default="cisco_ios", help="Netmiko device_type string"
    )
    p.add_argument(
        "--config", required=True, type=Path, help="File of config lines to apply"
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=60,
        metavar="SECS",
        help="Seconds before auto-revert if unconfirmed",
    )
    p.add_argument(
        "--checkpoint-dir",
        type=Path,
        default=Path("checkpoints"),
        help="Directory for checkpoint files",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port")
    p.add_argument(
        "--yes",
        action="store_true",
        help="Skip interactive prompt and keep changes automatically",
    )
    return p.parse_args()


def load_config_lines(path: Path) -> list:
    if not path.exists():
        log.error("Config file not found: %s", path)
        sys.exit(1)
    lines = [
        ln.rstrip()
        for ln in path.read_text().splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]
    if not lines:
        log.error("Config file is empty or contains only comments.")
        sys.exit(1)
    return lines


def main() -> int:
    args = parse_args()
    config_lines = load_config_lines(args.config)

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "timeout": 30,
        "session_log": f"session_{args.device.replace('.', '_')}.log",
    }

    try:
        log.info("Connecting to %s (%s)...", args.device, args.device_type)
        with ConnectHandler(**device_params) as conn:
            checkpoint = capture_running_config(conn, args.device_type)
            save_checkpoint(checkpoint, args.device, args.checkpoint_dir)

            output = apply_config(conn, config_lines)
            log.info("Apply output:\n%s", output.strip())

            if args.yes:
                log.info("--yes flag set; keeping changes.")
                conn.save_config()
                log.info("Configuration saved successfully.")
                return 0

            confirmed = wait_for_confirmation(args.timeout)

            if confirmed:
                log.info("Operator confirmed — saving config.")
                conn.save_config()
                log.info("Changes committed and saved.")
                return 0

            restore_checkpoint(conn, checkpoint)
            conn.save_config()
            log.info("Device restored to pre-change checkpoint.")
            return 1

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        return 2
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s:%s", args.device, args.port)
        return 2
    except KeyboardInterrupt:
        log.warning("Interrupted — changes may be partially applied. Check the device.")
        return 3
    except Exception as exc:
        log.exception("Unexpected error: %s", exc)
        return 3


if __name__ == "__main__":
    sys.exit(main())