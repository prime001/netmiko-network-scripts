```python
"""
config_rollback_v3.py - Archive diff and selective rollback for Cisco IOS devices.

Purpose:
    Retrieves the running configuration from a device, compares it against a locally
    stored baseline archive using unified diff, and optionally applies the archive as
    a rollback. Supports section-level filtering (e.g., only diff 'interface' blocks)
    to avoid noisy full-config comparisons.

Usage:
    python config_rollback_v3.py --host 192.168.1.1 --username admin --password secret \\
        --archive baseline.cfg [--section interface] [--dry-run] [--apply]

Prerequisites:
    pip install netmiko
    A saved baseline config file on disk.
    SSH access to target device with sufficient privilege level.
"""

import argparse
import difflib
import logging
import sys
from pathlib import Path

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


def get_running_config(conn):
    log.info("Fetching running configuration")
    return conn.send_command("show running-config", read_timeout=60).splitlines()


def load_archive(path):
    p = Path(path)
    if not p.exists():
        log.error("Archive file not found: %s", path)
        sys.exit(1)
    return p.read_text().splitlines()


def filter_section(lines, keyword):
    """Return lines belonging to config blocks that start with keyword."""
    result = []
    in_block = False
    for line in lines:
        if line.lower().startswith(keyword.lower()) and not line.startswith(" "):
            in_block = True
        elif in_block and line and not line.startswith(" ") and not line.startswith("!"):
            in_block = False
        if in_block:
            result.append(line)
    return result


def compute_diff(archive_lines, running_lines):
    return list(difflib.unified_diff(
        archive_lines,
        running_lines,
        fromfile="archive",
        tofile="running",
        lineterm="",
    ))


def apply_rollback(conn, lines):
    commands = [l for l in lines if l.strip() and not l.startswith("!")]
    log.info("Pushing %d config lines to device", len(commands))
    output = conn.send_config_set(commands, read_timeout=120)
    conn.save_config()
    log.info("Configuration saved to NVRAM")
    return output


def print_diff_summary(diff):
    added = sum(1 for l in diff if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in diff if l.startswith("-") and not l.startswith("---"))
    print("\n".join(diff))
    print(f"\nSummary: +{added} lines, -{removed} lines vs archive")


def main():
    parser = argparse.ArgumentParser(
        description="Diff running config against a saved archive and optionally roll back"
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument("--archive", required=True, help="Path to baseline config file")
    parser.add_argument(
        "--section",
        metavar="KEYWORD",
        help="Limit diff/rollback to config blocks starting with KEYWORD (e.g. 'interface')",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show diff only; do not apply changes",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply archive config as rollback after confirming diff",
    )
    parser.add_argument("--device-type", default="cisco_ios", help="Netmiko device type")
    parser.add_argument("--port", type=int, default=22)
    args = parser.parse_args()

    if args.dry_run and args.apply:
        parser.error("--dry-run and --apply are mutually exclusive")

    archive_lines = load_archive(args.archive)

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }

    try:
        log.info("Connecting to %s", args.host)
        with ConnectHandler(**device) as conn:
            running_lines = get_running_config(conn)

            if args.section:
                archive_cmp = filter_section(archive_lines, args.section)
                running_cmp = filter_section(running_lines, args.section)
                if not archive_cmp:
                    log.warning("Section '%s' not found in archive", args.section)
                if not running_cmp:
                    log.warning("Section '%s' not found in running config", args.section)
            else:
                archive_cmp = archive_lines
                running_cmp = running_lines

            diff = compute_diff(archive_cmp, running_cmp)

            if not diff:
                print("No differences found — running config matches archive.")
                return

            print(f"\nDiff for {args.host}" + (f" [section: {args.section}]" if args.section else "") + ":")
            print_diff_summary(diff)

            if args.dry_run:
                log.info("Dry-run complete; no changes applied")
                return

            if args.apply:
                confirm = input("\nApply archive as rollback? [yes/no]: ").strip().lower()
                if confirm != "yes":
                    log.info("Rollback cancelled")
                    return
                rollback_lines = archive_cmp if args.section else archive_lines
                apply_rollback(conn, rollback_lines)
                log.info("Rollback applied successfully")
            else:
                log.info("Pass --apply to push the archive, or --dry-run to suppress this hint")

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        sys.exit(1)
    except KeyboardInterrupt:
        log.warning("Interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
```