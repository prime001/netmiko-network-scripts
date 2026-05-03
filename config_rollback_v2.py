```python
"""
022_config_checkpoint_rollback.py — Checkpoint-based config rollback with diff verification.

Saves a timestamped running-config checkpoint before any change window, then
restores it line-by-line if needed. Shows a unified diff between the live
config and the checkpoint so operators can confirm exactly what will be
reverted before committing.

Usage:
    # Save a checkpoint before maintenance:
    python 022_config_checkpoint_rollback.py --host 10.0.0.1 --user admin \
        --password secret --action checkpoint --out backups/core1_pre.txt

    # Review what would be reverted (dry-run):
    python 022_config_checkpoint_rollback.py --host 10.0.0.1 --user admin \
        --password secret --action diff --checkpoint backups/core1_pre.txt

    # Perform the rollback:
    python 022_config_checkpoint_rollback.py --host 10.0.0.1 --user admin \
        --password secret --action rollback --checkpoint backups/core1_pre.txt

Prerequisites:
    pip install netmiko
    Tested against Cisco IOS / IOS-XE. Device type defaults to cisco_ios;
    pass --device-type for other platforms (e.g. cisco_nxos, arista_eos).
"""

import argparse
import difflib
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def fetch_running_config(conn) -> list[str]:
    log.info("Fetching running-config from device")
    raw = conn.send_command("show running-config", read_timeout=60)
    lines = [l.rstrip() for l in raw.splitlines()]
    # Strip the header lines that change on every capture (timestamp, etc.)
    return [l for l in lines if not l.startswith("! Last config") and l != "!"]


def save_checkpoint(conn, outfile: Path) -> None:
    lines = fetch_running_config(conn)
    outfile.parent.mkdir(parents=True, exist_ok=True)
    outfile.write_text("\n".join(lines) + "\n")
    log.info("Checkpoint saved → %s (%d lines)", outfile, len(lines))


def load_checkpoint(checkpoint: Path) -> list[str]:
    if not checkpoint.exists():
        log.error("Checkpoint file not found: %s", checkpoint)
        sys.exit(1)
    lines = [l.rstrip() for l in checkpoint.read_text().splitlines()]
    log.info("Loaded checkpoint: %s (%d lines)", checkpoint, len(lines))
    return lines


def compute_diff(current: list[str], target: list[str]) -> list[str]:
    return list(
        difflib.unified_diff(
            current,
            target,
            fromfile="running-config (live)",
            tofile="checkpoint (target)",
            lineterm="",
        )
    )


def apply_rollback(conn, target_lines: list[str], dry_run: bool = False) -> None:
    """Send the checkpoint config line-by-line inside a config session."""
    config_lines = [
        l for l in target_lines
        if l and not l.startswith("!")
    ]
    if dry_run:
        log.info("Dry-run: would send %d config lines — no changes applied", len(config_lines))
        return

    log.info("Applying rollback (%d config lines) …", len(config_lines))
    output = conn.send_config_set(
        config_lines,
        read_timeout=120,
        cmd_verify=False,
    )
    if conn.check_config_mode():
        conn.exit_config_mode()

    error_keywords = ("invalid input", "incomplete command", "ambiguous command")
    errors = [l for l in output.splitlines() if any(k in l.lower() for k in error_keywords)]
    if errors:
        log.warning("Config errors detected during rollback:")
        for e in errors:
            log.warning("  %s", e)
    else:
        log.info("Rollback applied cleanly")

    conn.save_config()
    log.info("Running-config saved to startup-config")


def build_connection(args) -> dict:
    return {
        "device_type": args.device_type,
        "host": args.host,
        "port": args.port,
        "username": args.user,
        "password": args.password,
        "secret": args.enable or args.password,
        "global_delay_factor": 2,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Checkpoint-based config rollback with diff preview",
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument("--enable", default=None, help="Enable secret (defaults to password)")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--device-type", default="cisco_ios", dest="device_type")
    parser.add_argument(
        "--action",
        choices=["checkpoint", "diff", "rollback"],
        required=True,
        help="checkpoint=save snapshot  diff=preview changes  rollback=restore snapshot",
    )
    parser.add_argument(
        "--checkpoint",
        type=Path,
        default=None,
        help="Path to checkpoint file (required for diff/rollback actions)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output path for checkpoint action (auto-named if omitted)",
    )
    args = parser.parse_args()

    if args.action in ("diff", "rollback") and not args.checkpoint:
        parser.error("--checkpoint is required for diff and rollback actions")

    if args.action == "checkpoint" and args.out is None:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.out = Path(f"backups/{args.host}_{stamp}.txt")

    params = build_connection(args)

    try:
        log.info("Connecting to %s:%d as %s", args.host, args.port, args.user)
        with ConnectHandler(**params) as conn:
            conn.enable()

            if args.action == "checkpoint":
                save_checkpoint(conn, args.out)

            elif args.action == "diff":
                current = fetch_running_config(conn)
                target = load_checkpoint(args.checkpoint)
                diff = compute_diff(current, target)
                if not diff:
                    log.info("No differences — live config matches checkpoint")
                else:
                    print("\n".join(diff))
                    log.info("%d diff lines (+ adds to live, - removes from live)", len(diff))

            elif args.action == "rollback":
                current = fetch_running_config(conn)
                target = load_checkpoint(args.checkpoint)
                diff = compute_diff(current, target)
                if not diff:
                    log.info("Live config already matches checkpoint — nothing to do")
                    return
                log.info("Diff summary: %d lines changed", len(diff))
                apply_rollback(conn, target)

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