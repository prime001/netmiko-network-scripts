```python
"""
014_pre_post_snapshot.py — Pre/Post Change Snapshot Comparator

Captures device state before and after a maintenance window, then diffs the
snapshots and flags critical changes (interface state flaps, route additions/
removals, neighbor state changes).

Usage:
    # Capture pre-change baseline:
    python 014_pre_post_snapshot.py --host 10.0.0.1 --user admin --pre

    # After the change, capture post and compare:
    python 014_pre_post_snapshot.py --host 10.0.0.1 --user admin --post

    # Compare two existing snapshot files explicitly:
    python 014_pre_post_snapshot.py --compare pre.json post.json

Prerequisites:
    pip install netmiko
    Python 3.8+
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from getpass import getpass
from pathlib import Path

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

SNAPSHOT_COMMANDS = [
    "show interfaces status",
    "show ip route summary",
    "show ip bgp summary",
    "show spanning-tree summary",
    "show ip ospf neighbor",
    "show version",
]

CRITICAL_KEYWORDS = {"down", "err-disabled", "idle", "active", "notconnect"}


def connect(host: str, user: str, password: str, device_type: str = "cisco_ios"):
    log.info("Connecting to %s as %s", host, user)
    try:
        conn = ConnectHandler(
            device_type=device_type,
            host=host,
            username=user,
            password=password,
            timeout=20,
        )
        log.info("Connected — %s", conn.find_prompt())
        return conn
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", user, host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Timeout connecting to %s", host)
        sys.exit(1)


def capture_snapshot(conn, commands: list[str]) -> dict:
    snapshot = {"timestamp": datetime.utcnow().isoformat(), "outputs": {}}
    for cmd in commands:
        log.info("Running: %s", cmd)
        try:
            output = conn.send_command(cmd, read_timeout=30)
            snapshot["outputs"][cmd] = output
        except Exception as exc:
            log.warning("Command failed (%s): %s", cmd, exc)
            snapshot["outputs"][cmd] = f"ERROR: {exc}"
    return snapshot


def save_snapshot(snapshot: dict, path: Path) -> None:
    path.write_text(json.dumps(snapshot, indent=2))
    log.info("Snapshot saved → %s", path)


def load_snapshot(path: Path) -> dict:
    if not path.exists():
        log.error("Snapshot file not found: %s", path)
        sys.exit(1)
    return json.loads(path.read_text())


def diff_outputs(pre_text: str, post_text: str) -> list[str]:
    pre_lines = set(pre_text.splitlines())
    post_lines = set(post_text.splitlines())
    removed = [f"  - {l}" for l in sorted(pre_lines - post_lines) if l.strip()]
    added = [f"  + {l}" for l in sorted(post_lines - pre_lines) if l.strip()]
    return removed + added


def flag_critical(diff_lines: list[str]) -> list[str]:
    return [l for l in diff_lines if any(kw in l.lower() for kw in CRITICAL_KEYWORDS)]


def compare_snapshots(pre: dict, post: dict) -> int:
    print(f"\n{'='*60}")
    print(f"PRE  snapshot: {pre['timestamp']}")
    print(f"POST snapshot: {post['timestamp']}")
    print(f"{'='*60}\n")

    critical_total = 0
    commands = set(pre["outputs"]) | set(post["outputs"])

    for cmd in sorted(commands):
        pre_out = pre["outputs"].get(cmd, "(missing)")
        post_out = post["outputs"].get(cmd, "(missing)")
        diff = diff_outputs(pre_out, post_out)
        if not diff:
            print(f"[OK] {cmd}")
            continue

        critical = flag_critical(diff)
        critical_total += len(critical)
        marker = "[CRITICAL]" if critical else "[CHANGED]"
        print(f"\n{marker} {cmd}")
        for line in diff:
            print(f"    {line}")

    print(f"\n{'='*60}")
    if critical_total:
        print(f"RESULT: FAIL — {critical_total} critical change(s) detected")
    else:
        print("RESULT: PASS — no critical state changes")
    print(f"{'='*60}\n")
    return 1 if critical_total else 0


def snapshot_path(host: str, phase: str) -> Path:
    safe = host.replace(".", "_")
    return Path(f"{safe}_{phase}_snapshot.json")


def parse_args():
    p = argparse.ArgumentParser(description="Pre/post change snapshot comparator")
    p.add_argument("--host", help="Device IP or hostname")
    p.add_argument("--user", help="SSH username")
    p.add_argument("--device-type", default="cisco_ios", help="Netmiko device type")
    p.add_argument("--pre", action="store_true", help="Capture pre-change snapshot")
    p.add_argument("--post", action="store_true", help="Capture post-change snapshot and compare")
    p.add_argument("--compare", nargs=2, metavar=("PRE", "POST"),
                   help="Compare two existing snapshot files")
    p.add_argument("--commands", nargs="+", metavar="CMD",
                   help="Override default show commands")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.compare:
        pre_snap = load_snapshot(Path(args.compare[0]))
        post_snap = load_snapshot(Path(args.compare[1]))
        sys.exit(compare_snapshots(pre_snap, post_snap))

    if not args.pre and not args.post:
        log.error("Specify --pre, --post, or --compare PRE POST")
        sys.exit(1)

    if not args.host:
        log.error("--host is required for live capture")
        sys.exit(1)

    user = args.user or input("Username: ")
    password = getpass("Password: ")
    commands = args.commands or SNAPSHOT_COMMANDS

    conn = connect(args.host, user, password, args.device_type)
    try:
        snapshot = capture_snapshot(conn, commands)
    finally:
        conn.disconnect()

    phase = "pre" if args.pre else "post"
    out_path = snapshot_path(args.host, phase)
    save_snapshot(snapshot, out_path)

    if args.post:
        pre_path = snapshot_path(args.host, "pre")
        pre_snap = load_snapshot(pre_path)
        sys.exit(compare_snapshots(pre_snap, snapshot))
```