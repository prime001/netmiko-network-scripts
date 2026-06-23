#!/usr/bin/env python3
"""
config_backup.py - Network device configuration backup and drift detection

Purpose:
    Archives running configurations from network devices to timestamped files
    and detects configuration drift by comparing against the most recent backup.
    Useful for compliance auditing, change tracking, and pre/post-change snapshots.

Usage:
    # Single device backup
    python config_backup.py --host 10.0.0.1 --username admin --password secret

    # Bulk backup from inventory file (one IP/hostname per line, # for comments)
    python config_backup.py --inventory hosts.txt --username admin --password secret

    # Show unified diff against previous backup (also saves new backup)
    python config_backup.py --host 10.0.0.1 --diff

    # Use environment variables for credentials
    NET_USER=admin NET_PASS=secret python config_backup.py --host 10.0.0.1

Prerequisites:
    pip install netmiko
"""

import argparse
import difflib
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

SHOW_RUN = {
    "cisco_ios": "show running-config",
    "cisco_xe": "show running-config",
    "cisco_nxos": "show running-config",
    "arista_eos": "show running-config",
    "juniper_junos": "show configuration | display set",
}


def fetch_config(host, username, password, device_type, port):
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
    }
    command = SHOW_RUN.get(device_type, "show running-config")
    log.info("Connecting to %s (%s)", host, device_type)
    with ConnectHandler(**params) as conn:
        return conn.send_command(command, read_timeout=60)


def save_backup(host, config, output_dir):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = Path(output_dir) / host
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / f"{ts}_running.cfg"
    path.write_text(config)
    log.info("Saved %s", path)
    return path


def latest_backup(host, output_dir):
    device_dir = Path(output_dir) / host
    if not device_dir.exists():
        return None
    candidates = sorted(device_dir.glob("*_running.cfg"))
    return candidates[-1] if candidates else None


def print_drift(host, current_config, output_dir):
    prev_path = latest_backup(host, output_dir)
    if prev_path is None:
        log.warning("[%s] No prior backup found; skipping diff", host)
        return

    prev_lines = prev_path.read_text().splitlines(keepends=True)
    curr_lines = current_config.splitlines(keepends=True)
    diff = list(difflib.unified_diff(
        prev_lines,
        curr_lines,
        fromfile=str(prev_path),
        tofile=f"{host} (live)",
    ))

    if diff:
        print(f"\n--- Config drift on {host} ({len(diff)} diff lines) ---")
        sys.stdout.writelines(diff)
    else:
        print(f"[{host}] No drift detected since {prev_path.name}")


def backup_device(host, username, password, device_type, port, output_dir, show_diff):
    try:
        config = fetch_config(host, username, password, device_type, port)
    except NetmikoAuthenticationException:
        log.error("[%s] Authentication failed", host)
        return False
    except NetmikoTimeoutException:
        log.error("[%s] Connection timed out", host)
        return False
    except Exception as exc:
        log.error("[%s] %s", host, exc)
        return False

    if show_diff:
        print_drift(host, config, output_dir)

    save_backup(host, config, output_dir)
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Backup network device running configs and detect configuration drift"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="Single device IP or hostname")
    group.add_argument("--inventory", help="Inventory file with one host per line")
    parser.add_argument("--username", default=os.environ.get("NET_USER"))
    parser.add_argument("--password", default=os.environ.get("NET_PASS"))
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(SHOW_RUN.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--output-dir",
        default="config_backups",
        help="Root directory for backup storage (default: config_backups)",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Print unified diff against most recent backup before saving new one",
    )
    args = parser.parse_args()

    if not args.username or not args.password:
        parser.error(
            "Credentials required via --username/--password or NET_USER/NET_PASS env vars"
        )

    if args.host:
        hosts = [args.host]
    else:
        p = Path(args.inventory)
        if not p.exists():
            parser.error(f"Inventory file not found: {args.inventory}")
        hosts = [
            ln.strip()
            for ln in p.read_text().splitlines()
            if ln.strip() and not ln.startswith("#")
        ]
        if not hosts:
            parser.error("Inventory file contains no valid hosts")

    succeeded, failed = 0, 0
    for host in hosts:
        ok = backup_device(
            host,
            args.username,
            args.password,
            args.device_type,
            args.port,
            args.output_dir,
            args.diff,
        )
        if ok:
            succeeded += 1
        else:
            failed += 1

    log.info("Complete: %d succeeded, %d failed", succeeded, failed)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()