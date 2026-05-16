Here is the script:

```python
"""
interface_baseline.py - Interface error/counter baseline capture and comparison.

Purpose:
    Captures interface error counters and link status before a maintenance window,
    then compares against a post-change capture to flag any interfaces that accrued
    new errors or changed link state. Useful after cable swaps, optic replacements,
    patch panel work, or any physical layer change where silent error accumulation
    is the failure mode.

Usage:
    # Step 1 — save a baseline before the change:
    python interface_baseline.py --host 192.168.1.1 -u admin -p secret \
        --mode capture --snapshot pre_change.json

    # Step 2 — after the change, capture and compare in one shot:
    python interface_baseline.py --host 192.168.1.1 -u admin -p secret \
        --mode compare --baseline pre_change.json --snapshot post_change.json

    # Diff two existing snapshot files without connecting to a device:
    python interface_baseline.py --mode diff \
        --baseline pre_change.json --snapshot post_change.json

Prerequisites:
    pip install netmiko
    Tested against Cisco IOS/IOS-XE. Device must permit 'show interfaces'.
    Exit code 0 = clean, 1 = issues found (CRC errors, status changes, threshold exceeded).
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

_ERROR_FIELDS = {
    "input_errors": r"(\d+) input errors",
    "crc": r"(\d+) CRC",
    "frame": r"(\d+) frame",
    "overrun": r"(\d+) overrun",
    "ignored": r"(\d+) ignored",
    "input_drops": r"(\d+) input drops",
    "output_errors": r"(\d+) output errors",
    "collisions": r"(\d+) collisions",
    "output_drops": r"(\d+) output drops",
    "late_collisions": r"(\d+) late collision",
    "resets": r"(\d+) resets",
}


def _parse_interfaces(raw: str) -> dict:
    interfaces = {}
    for block in re.split(r"\n(?=\S)", raw):
        m = re.match(r"^(\S+)\s+is\s+(up|down|administratively down)", block)
        if not m:
            continue
        counters = {"status": m.group(2)}
        for field, pattern in _ERROR_FIELDS.items():
            hit = re.search(pattern, block, re.IGNORECASE)
            counters[field] = int(hit.group(1)) if hit else 0
        interfaces[m.group(1)] = counters
    return interfaces


def capture_snapshot(host: str, username: str, password: str, device_type: str) -> dict:
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "timeout": 30,
    }
    log.info("Connecting to %s", host)
    try:
        with ConnectHandler(**params) as conn:
            log.info("Connected — capturing interface counters")
            raw = conn.send_command("show interfaces", read_timeout=60)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", username, host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", host)
        sys.exit(1)

    interfaces = _parse_interfaces(raw)
    log.info("Captured %d interfaces", len(interfaces))
    return {
        "host": host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "interfaces": interfaces,
    }


def _save(snapshot: dict, path: str) -> None:
    Path(path).write_text(json.dumps(snapshot, indent=2))
    log.info("Snapshot written to %s", path)


def _load(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        log.error("File not found: %s", path)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        log.error("Cannot parse %s: %s", path, exc)
        sys.exit(1)


def compare(baseline: dict, current: dict, threshold: int) -> list:
    issues = []
    for iface, curr in current["interfaces"].items():
        base = baseline["interfaces"].get(iface)
        if base is None:
            continue
        deltas = {
            f: curr.get(f, 0) - base.get(f, 0)
            for f in _ERROR_FIELDS
            if curr.get(f, 0) - base.get(f, 0) > 0
        }
        hard_errors = sum(
            v for f, v in deltas.items() if f not in ("input_drops", "output_drops")
        )
        status_changed = base["status"] != curr["status"]
        if hard_errors > threshold or status_changed or deltas.get("crc", 0) > 0:
            issues.append({
                "interface": iface,
                "baseline_status": base["status"],
                "current_status": curr["status"],
                "status_changed": status_changed,
                "error_deltas": deltas,
                "total_new_errors": hard_errors,
            })
    return sorted(issues, key=lambda x: x["total_new_errors"], reverse=True)


def print_report(baseline: dict, current: dict, issues: list, threshold: int) -> None:
    sep = "=" * 68
    print(f"\n{sep}")
    print("INTERFACE BASELINE COMPARISON REPORT")
    print(sep)
    print(f"Host:         {current['host']}")
    print(f"Baseline:     {baseline['timestamp']}")
    print(f"Post-change:  {current['timestamp']}")
    print(f"Threshold:    {threshold} new errors to flag")
    print(f"Checked:      {len(current['interfaces'])} interfaces")
    print(sep)

    if not issues:
        print("\n  PASS — no interfaces exceeded error thresholds.\n")
        print(sep + "\n")
        return

    print(f"\n  WARNING — {len(issues)} interface(s) flagged:\n")
    for item in issues:
        status_note = (
            f"  [status: {item['baseline_status']} -> {item['current_status']}]"
            if item["status_changed"] else ""
        )
        print(f"  {item['interface']}{status_note}")
        for field, delta in item["error_deltas"].items():
            print(f"    {field:<20} +{delta}")
        print()

    result = "FAIL" if any(i["error_deltas"].get("crc", 0) > 0 for i in issues) else "WARN"
    print(f"{sep}\nResult: {result}\n{sep}\n")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Capture and compare interface error baselines across a change window."
    )
    p.add_argument("--host", help="Device IP or hostname")
    p.add_argument("--username", "-u", help="SSH username")
    p.add_argument("--password", "-p", help="SSH password")
    p.add_argument("--device-type", default="cisco_ios",
                   help="Netmiko device type (default: cisco_ios)")
    p.add_argument("--mode", required=True, choices=["capture", "compare", "diff"],
                   help="capture: save snapshot; compare: capture+diff; diff: compare two files")
    p.add_argument("--snapshot", required=True,
                   help="Output path for current/post-change snapshot")
    p.add_argument("--baseline", help="Baseline snapshot file (required for compare/diff)")
    p.add_argument("--threshold", type=int, default=10,
                   help="Hard error delta to flag an interface (default: 10)")
    return p


if __name__ == "__main__":
    parser = _build_parser()
    args = parser.parse_args()

    if args.mode in ("compare", "diff") and not args.baseline:
        parser.error("--baseline is required for compare and diff modes")

    if args.mode in ("capture", "compare"):
        if not all([args.host, args.username, args.password]):
            parser.error("--host, --username, and --password are required for capture/compare")
        current = capture_snapshot(args.host, args.username, args.password, args.device_type)
        _save(current, args.snapshot)
    else:
        current = _load(args.snapshot)

    if args.mode in ("compare", "diff"):
        baseline = _load(args.baseline)
        issues = compare(baseline, current, args.threshold)
        print_report(baseline, current, issues, args.threshold)
        sys.exit(1 if issues else 0)

    log.info("Done. Run with --mode compare --baseline %s after your change.", args.snapshot)
```