```python
"""
config_checkpoint.py — Named checkpoint management with diff-based rollback.

Saves timestamped config checkpoints to disk, shows unified diffs between
checkpoints and the live running config, and can restore any saved checkpoint
with pre/post connectivity verification.

Usage:
    # Save current config as a named checkpoint
    python config_checkpoint.py -H 10.0.0.1 -u admin -p secret --save nightly

    # List saved checkpoints
    python config_checkpoint.py -H 10.0.0.1 -u admin -p secret --list

    # Diff live config against a checkpoint
    python config_checkpoint.py -H 10.0.0.1 -u admin -p secret --diff nightly

    # Restore a checkpoint (dry-run first)
    python config_checkpoint.py -H 10.0.0.1 -u admin -p secret --restore nightly --dry-run
    python config_checkpoint.py -H 10.0.0.1 -u admin -p secret --restore nightly

Prerequisites:
    pip install netmiko
    Checkpoints stored in ./checkpoints/<hostname>/<label>_<timestamp>.cfg
"""

import argparse
import difflib
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

CHECKPOINT_DIR = Path("./checkpoints")
INDEX_FILE = "index.json"


def connect(host, username, password, device_type, port):
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "timeout": 30,
    }
    log.info("Connecting to %s (%s)", host, device_type)
    return ConnectHandler(**params)


def get_running_config(conn):
    output = conn.send_command("show running-config", read_timeout=60)
    if not output or "Invalid" in output:
        raise RuntimeError("Failed to retrieve running config")
    return output


def checkpoint_dir(host):
    path = CHECKPOINT_DIR / host
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_index(host):
    idx_path = checkpoint_dir(host) / INDEX_FILE
    if idx_path.exists():
        with open(idx_path) as f:
            return json.load(f)
    return {}


def save_index(host, index):
    idx_path = checkpoint_dir(host) / INDEX_FILE
    with open(idx_path, "w") as f:
        json.dump(index, f, indent=2)


def save_checkpoint(conn, host, label):
    config = get_running_config(conn)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{label}_{ts}.cfg"
    path = checkpoint_dir(host) / filename
    path.write_text(config)

    index = load_index(host)
    if label not in index:
        index[label] = []
    index[label].append({"file": filename, "timestamp": ts})
    save_index(host, index)

    log.info("Checkpoint '%s' saved: %s (%d lines)", label, filename, len(config.splitlines()))
    return path


def list_checkpoints(host):
    index = load_index(host)
    if not index:
        print(f"No checkpoints found for {host}")
        return
    print(f"\nCheckpoints for {host}:")
    print(f"  {'Label':<20} {'Saved':<20} {'File'}")
    print("  " + "-" * 70)
    for label, entries in sorted(index.items()):
        for entry in entries:
            ts = entry["timestamp"]
            fmt = datetime.strptime(ts, "%Y%m%d_%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
            print(f"  {label:<20} {fmt:<20} {entry['file']}")


def resolve_checkpoint_path(host, label):
    index = load_index(host)
    if label not in index or not index[label]:
        raise FileNotFoundError(f"No checkpoint found with label '{label}' for {host}")
    latest = sorted(index[label], key=lambda e: e["timestamp"])[-1]
    return checkpoint_dir(host) / latest["file"]


def diff_configs(live_config, checkpoint_path):
    saved = checkpoint_path.read_text()
    live_lines = live_config.splitlines(keepends=True)
    saved_lines = saved.splitlines(keepends=True)
    diff = list(difflib.unified_diff(
        saved_lines, live_lines,
        fromfile=f"checkpoint:{checkpoint_path.name}",
        tofile="running-config",
        lineterm="",
    ))
    return diff


def apply_rollback(conn, checkpoint_path, dry_run):
    saved_config = checkpoint_path.read_text()
    commands = [
        line.rstrip()
        for line in saved_config.splitlines()
        if line.strip() and not line.startswith("!")
        and not line.startswith("Building configuration")
        and not line.startswith("Current configuration")
    ]

    log.info("%s rollback from %s (%d commands)",
             "DRY RUN —" if dry_run else "Applying", checkpoint_path.name, len(commands))

    if dry_run:
        print("\n[DRY RUN] Commands that would be sent:")
        for cmd in commands[:20]:
            print(f"  {cmd}")
        if len(commands) > 20:
            print(f"  ... and {len(commands) - 20} more")
        return

    output = conn.send_config_set(commands, read_timeout=120)
    conn.save_config()
    log.info("Rollback applied and config saved")
    return output


def verify_connectivity(conn):
    output = conn.send_command("show ip interface brief")
    up_count = output.count(" up ")
    log.info("Post-rollback interface check: %d interfaces up", up_count)
    return up_count > 0


def parse_args():
    parser = argparse.ArgumentParser(
        description="Netmiko config checkpoint manager — save, diff, and restore device configs"
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument(
        "-t", "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)"
    )
    parser.add_argument("--port", type=int, default=22)

    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--save", metavar="LABEL", help="Save running config as named checkpoint")
    action.add_argument("--list", action="store_true", help="List saved checkpoints")
    action.add_argument("--diff", metavar="LABEL", help="Diff live config against checkpoint")
    action.add_argument("--restore", metavar="LABEL", help="Restore a saved checkpoint")

    parser.add_argument(
        "--dry-run", action="store_true",
        help="With --restore: show commands without applying"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.list:
        list_checkpoints(args.host)
        return

    try:
        conn = connect(args.host, args.username, args.password, args.device_type, args.port)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        sys.exit(1)

    try:
        if args.save:
            save_checkpoint(conn, args.host, args.save)

        elif args.diff:
            ckpt_path = resolve_checkpoint_path(args.host, args.diff)
            live = get_running_config(conn)
            diff = diff_configs(live, ckpt_path)
            if not diff:
                print("No differences — running config matches checkpoint.")
            else:
                print(f"\nDiff (checkpoint → live): {len(diff)} changed lines\n")
                print("".join(diff))

        elif args.restore:
            ckpt_path = resolve_checkpoint_path(args.host, args.restore)
            live = get_running_config(conn)
            diff = diff_configs(live, ckpt_path)
            if not diff:
                log.info("Running config already matches checkpoint — nothing to restore")
                return
            log.info("Detected %d differing lines before restore", len(diff))
            apply_rollback(conn, ckpt_path, dry_run=args.dry_run)
            if not args.dry_run:
                ok = verify_connectivity(conn)
                if not ok:
                    log.warning("No interfaces are up post-rollback — verify manually")

    except FileNotFoundError as e:
        log.error("%s", e)
        sys.exit(1)
    except Exception as e:
        log.error("Unexpected error: %s", e)
        sys.exit(1)
    finally:
        conn.disconnect()


if __name__ == "__main__":
    main()
```