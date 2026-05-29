The brainstorming skill applies to open-ended design, but the user has provided a complete spec with all requirements. User instructions take precedence — outputting the script directly.

"""
config_diff.py - Running configuration drift detection and diff tool

Purpose:
    Compare a device's running configuration against a saved baseline file or
    a second live device. Detects drift after changes, validates expected state
    before/after maintenance, and provides context for rollback decisions.

Usage:
    # Diff running config against a local baseline
    python config_diff.py --host 192.168.1.1 --username admin --baseline saved.cfg

    # Diff two live devices (verify HA pairs or redundant paths match)
    python config_diff.py --host 192.168.1.1 --compare 192.168.1.2 --username admin

    # Capture a timestamped snapshot without diffing
    python config_diff.py --host 192.168.1.1 --username admin --snapshot

Prerequisites:
    pip install netmiko
    SSH must be enabled on target device(s).
    Tested with Cisco IOS/IOS-XE; adjust --device-type for other platforms.
"""

import argparse
import difflib
import getpass
import logging
import sys
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

_GREEN = "\033[32m" if sys.stdout.isatty() else ""
_RED = "\033[31m" if sys.stdout.isatty() else ""
_RESET = "\033[0m" if sys.stdout.isatty() else ""


def fetch_config(host, username, password, device_type, port):
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
    }
    try:
        logger.info("Connecting to %s", host)
        with ConnectHandler(**params) as conn:
            config = conn.send_command("show running-config")
        logger.info("Retrieved config from %s (%d lines)", host, config.count("\n"))
        return config
    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s", host)
        raise
    except NetmikoTimeoutException:
        logger.error("Connection timed out for %s", host)
        raise


def save_snapshot(host, config, output_dir):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_host = host.replace(".", "_")
    path = Path(output_dir) / f"{safe_host}_{ts}.cfg"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(config)
    logger.info("Snapshot saved: %s", path)
    return path


def diff_configs(config_a, config_b, label_a, label_b):
    lines_a = config_a.splitlines(keepends=True)
    lines_b = config_b.splitlines(keepends=True)
    return list(difflib.unified_diff(lines_a, lines_b, fromfile=label_a, tofile=label_b))


def render_diff(diff):
    if not diff:
        print("No differences found — configs match.")
        return 0

    added = sum(1 for ln in diff if ln.startswith("+") and not ln.startswith("+++"))
    removed = sum(1 for ln in diff if ln.startswith("-") and not ln.startswith("---"))

    for line in diff:
        if line.startswith("+") and not line.startswith("+++"):
            print(f"{_GREEN}{line}{_RESET}", end="")
        elif line.startswith("-") and not line.startswith("---"):
            print(f"{_RED}{line}{_RESET}", end="")
        else:
            print(line, end="")

    print(f"\nSummary: +{added} added, -{removed} removed")
    return added + removed


def build_parser():
    p = argparse.ArgumentParser(
        description=(
            "Detect config drift by diffing a device's running config "
            "against a baseline file or a second live device."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--host", required=True, help="Primary device IP or hostname")
    p.add_argument("--username", required=True, help="SSH username")
    p.add_argument("--password", help="SSH password (prompted if omitted)")
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--output-dir",
        default="snapshots",
        help="Directory for snapshot files (default: snapshots/)",
    )
    p.add_argument(
        "--save",
        action="store_true",
        help="Save retrieved config(s) as snapshots even when diffing",
    )

    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--baseline",
        metavar="FILE",
        help="Local config file to diff the running config against",
    )
    mode.add_argument(
        "--compare",
        metavar="HOST",
        help="Second device to diff against (fetches its running config live)",
    )
    mode.add_argument(
        "--snapshot",
        action="store_true",
        help="Capture and save the running config as a timestamped snapshot only",
    )
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    password = args.password or getpass.getpass(
        f"Password for {args.username}@{args.host}: "
    )

    try:
        config_primary = fetch_config(
            args.host, args.username, password, args.device_type, args.port
        )
    except (NetmikoAuthenticationException, NetmikoTimeoutException):
        sys.exit(1)
    except Exception as exc:
        logger.error("Unexpected error connecting to %s: %s", args.host, exc)
        sys.exit(1)

    if args.snapshot:
        save_snapshot(args.host, config_primary, args.output_dir)
        return

    if args.save:
        save_snapshot(args.host, config_primary, args.output_dir)

    if args.baseline:
        baseline_path = Path(args.baseline)
        if not baseline_path.exists():
            logger.error("Baseline file not found: %s", args.baseline)
            sys.exit(1)
        config_ref = baseline_path.read_text()
        diff = diff_configs(config_ref, config_primary, str(baseline_path), args.host)
    else:
        try:
            config_ref = fetch_config(
                args.compare, args.username, password, args.device_type, args.port
            )
        except (NetmikoAuthenticationException, NetmikoTimeoutException):
            sys.exit(1)
        except Exception as exc:
            logger.error("Unexpected error connecting to %s: %s", args.compare, exc)
            sys.exit(1)
        if args.save:
            save_snapshot(args.compare, config_ref, args.output_dir)
        diff = diff_configs(config_primary, config_ref, args.host, args.compare)

    changes = render_diff(diff)
    sys.exit(0 if changes == 0 else 1)


if __name__ == "__main__":
    main()