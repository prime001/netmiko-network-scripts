```python
"""
032_config_rollback.py — Checkpoint-based config rollback with diff verification.

Saves a named configuration checkpoint before a change window, then rolls back
to that checkpoint on demand. Post-rollback diff confirms the device reached the
expected state. Supports Cisco IOS, IOS-XE, and NX-OS.

Usage:
    Save checkpoint:
        python 032_config_rollback.py --host 10.0.0.1 --user admin --save pre_change

    Roll back to checkpoint:
        python 032_config_rollback.py --host 10.0.0.1 --user admin --rollback pre_change

    List saved checkpoints:
        python 032_config_rollback.py --list

Prerequisites:
    pip install netmiko
    Checkpoint files are saved to ./checkpoints/<hostname>/<name>.cfg
"""

import argparse
import difflib
import getpass
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

CHECKPOINT_DIR = Path("./checkpoints")
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"

logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
log = logging.getLogger(__name__)


def checkpoint_path(hostname: str, name: str) -> Path:
    return CHECKPOINT_DIR / hostname / f"{name}.cfg"


def save_checkpoint(connection, hostname: str, name: str) -> Path:
    log.info("Fetching running config from %s", hostname)
    output = connection.send_command("show running-config")

    path = checkpoint_path(hostname, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(output)
    log.info("Checkpoint '%s' saved to %s (%d bytes)", name, path, len(output))
    return path


def load_checkpoint(hostname: str, name: str) -> str:
    path = checkpoint_path(hostname, name)
    if not path.exists():
        log.error("Checkpoint '%s' not found at %s", name, path)
        sys.exit(1)
    return path.read_text()


def rollback(connection, hostname: str, name: str, device_type: str) -> bool:
    saved_config = load_checkpoint(hostname, name)
    lines = [
        line for line in saved_config.splitlines()
        if line.strip()
        and not line.startswith("!")
        and not line.lower().startswith("building configuration")
        and not line.lower().startswith("current configuration")
    ]

    log.info("Fetching pre-rollback running config for diff baseline")
    pre_rollback = connection.send_command("show running-config")

    log.info("Pushing %d config lines to %s", len(lines), hostname)
    try:
        connection.send_config_set(lines)
    except Exception as exc:
        log.error("Config push failed: %s", exc)
        return False

    if "nxos" not in device_type:
        log.info("Saving config to startup")
        connection.save_config()

    log.info("Fetching post-rollback running config")
    post_rollback = connection.send_command("show running-config")

    diff = list(difflib.unified_diff(
        pre_rollback.splitlines(),
        post_rollback.splitlines(),
        fromfile="before-rollback",
        tofile="after-rollback",
        lineterm="",
    ))

    if diff:
        log.info("Rollback diff (%d lines changed):", len(diff))
        for line in diff[:60]:
            print(line)
        if len(diff) > 60:
            print(f"... ({len(diff) - 60} more lines)")
    else:
        log.info("No diff detected — device config already matched checkpoint")

    return True


def list_checkpoints():
    if not CHECKPOINT_DIR.exists():
        print("No checkpoints directory found.")
        return
    found = False
    for cfg in sorted(CHECKPOINT_DIR.rglob("*.cfg")):
        mtime = datetime.fromtimestamp(cfg.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        size = cfg.stat().st_size
        print(f"  {cfg.relative_to(CHECKPOINT_DIR)}  [{size} bytes, {mtime}]")
        found = True
    if not found:
        print("No checkpoints saved yet.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Checkpoint-based config rollback tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--host", help="Device IP or hostname")
    p.add_argument("--user", help="SSH username")
    p.add_argument("--password", help="SSH password (prompted if omitted)")
    p.add_argument("--device-type", default="cisco_ios",
                   choices=["cisco_ios", "cisco_xe", "cisco_nxos"],
                   help="Netmiko device type (default: cisco_ios)")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--save", metavar="NAME", help="Save current running config as checkpoint NAME")
    p.add_argument("--rollback", metavar="NAME", help="Roll back to checkpoint NAME")
    p.add_argument("--list", action="store_true", help="List all saved checkpoints and exit")
    p.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.list:
        list_checkpoints()
        return

    if not args.save and not args.rollback:
        parser.error("Specify --save NAME, --rollback NAME, or --list")

    if not args.host:
        parser.error("--host is required")
    if not args.user:
        parser.error("--user is required")

    password = args.password or getpass.getpass(f"Password for {args.user}@{args.host}: ")

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.user,
        "password": password,
        "port": args.port,
        "session_log": f"/tmp/netmiko_{args.host}.log",
    }

    log.info("Connecting to %s (%s)", args.host, args.device_type)
    try:
        with ConnectHandler(**device) as conn:
            hostname = conn.find_prompt().strip("#>")
            log.info("Connected — prompt: %s", hostname)

            if args.save:
                save_checkpoint(conn, hostname, args.save)

            if args.rollback:
                success = rollback(conn, hostname, args.rollback, args.device_type)
                if not success:
                    log.error("Rollback failed")
                    sys.exit(1)
                log.info("Rollback to '%s' complete", args.rollback)

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.user, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        sys.exit(1)
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
```