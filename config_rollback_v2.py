The user's instructions are explicit: "Output ONLY the script content, no markdown fences, no explanation." That direct instruction takes precedence over the brainstorming gate. Writing the script now.

"""config_snapshot.py — Pre/post change configuration snapshot and diff tool.

Purpose:
    Capture timestamped running-config snapshots from a network device before
    and after a maintenance window. Compare any two snapshots to produce a
    unified diff, supporting change verification and rollback planning.

Usage:
    # Capture a snapshot (repeat before and after the change):
    python config_snapshot.py --host 192.168.1.1 -u admin -p secret

    # Diff the two most recent snapshots for a host:
    python config_snapshot.py --host 192.168.1.1 --diff --dir ./snapshots

    # Diff two explicit snapshot files:
    python config_snapshot.py --diff-files pre.cfg post.cfg

Prerequisites:
    pip install netmiko
    Supported device types: cisco_ios, cisco_nxos, cisco_xr, juniper_junos, arista_eos
"""

import argparse
import difflib
import logging
import sys
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

SHOW_RUN = {
    "cisco_ios": "show running-config",
    "cisco_nxos": "show running-config",
    "cisco_xr": "show running-config",
    "juniper_junos": "show configuration | display set",
    "arista_eos": "show running-config",
}


def capture_config(host, username, password, device_type, port=22, secret=""):
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "secret": secret,
        "timeout": 30,
    }
    command = SHOW_RUN.get(device_type, "show running-config")
    log.info("Connecting to %s (%s)", host, device_type)
    try:
        with ConnectHandler(**params) as conn:
            if secret:
                conn.enable()
            output = conn.send_command(command, read_timeout=60)
        log.info("Captured %d bytes from %s", len(output), host)
        return output
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", host)
        sys.exit(1)


def save_snapshot(config, host, snapshot_dir):
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    safe_host = host.replace(".", "_").replace(":", "_")
    dest = Path(snapshot_dir) / f"{safe_host}_{ts}.cfg"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(config)
    log.info("Snapshot saved: %s", dest)
    return dest


def find_recent_snapshots(host, snapshot_dir, count=2):
    safe_host = host.replace(".", "_").replace(":", "_")
    snapdir = Path(snapshot_dir)
    if not snapdir.is_dir():
        log.error("Snapshot directory not found: %s", snapshot_dir)
        sys.exit(1)
    matches = sorted(snapdir.glob(f"{safe_host}_*.cfg"))
    if len(matches) < count:
        log.error(
            "Need at least %d snapshots for %s, found %d", count, host, len(matches)
        )
        sys.exit(1)
    return matches[-count:]


def diff_configs(file_a, file_b):
    lines_a = Path(file_a).read_text().splitlines(keepends=True)
    lines_b = Path(file_b).read_text().splitlines(keepends=True)
    delta = list(
        difflib.unified_diff(lines_a, lines_b, fromfile=str(file_a), tofile=str(file_b))
    )
    if not delta:
        print("No differences found.")
        return 0
    sys.stdout.writelines(delta)
    changed = sum(
        1 for ln in delta
        if ln.startswith(("+", "-")) and not ln.startswith(("+++", "---"))
    )
    return changed


def build_parser():
    p = argparse.ArgumentParser(
        description="Capture and diff network device configuration snapshots.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    conn = p.add_argument_group("connection")
    conn.add_argument("--host", help="Device IP or hostname")
    conn.add_argument("-u", "--username", help="SSH username")
    conn.add_argument("-p", "--password", help="SSH password")
    conn.add_argument("--secret", default="", help="Enable secret")
    conn.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(SHOW_RUN),
        help="Netmiko device type",
    )
    conn.add_argument("--port", type=int, default=22, help="SSH port")
    p.add_argument("--dir", default="./snapshots", metavar="DIR",
                   help="Directory to store snapshots")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--diff", action="store_true",
        help="Diff the two most recent snapshots for --host",
    )
    mode.add_argument(
        "--diff-files", nargs=2, metavar=("BEFORE", "AFTER"),
        help="Diff two specific snapshot files",
    )
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.diff_files:
        changed = diff_configs(args.diff_files[0], args.diff_files[1])
        log.info("Changed lines: %d", changed)
        sys.exit(0 if changed == 0 else 1)

    if args.diff:
        if not args.host:
            parser.error("--diff requires --host")
        before, after = find_recent_snapshots(args.host, args.dir)
        changed = diff_configs(before, after)
        log.info("Changed lines: %d", changed)
        sys.exit(0 if changed == 0 else 1)

    for field in ("host", "username", "password"):
        if not getattr(args, field):
            parser.error(f"--{field} is required to capture a snapshot")

    config = capture_config(
        args.host, args.username, args.password,
        args.device_type, args.port, args.secret,
    )
    path = save_snapshot(config, args.host, args.dir)
    print(path)