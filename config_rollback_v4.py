```python
"""
config_drift_detector.py - Network Configuration Drift Detection

Purpose:
    Connects to network devices via SSH/Netmiko, captures running configurations
    as timestamped snapshots, and detects drift by comparing the current config
    against a saved baseline. Useful for change auditing, compliance checks, and
    catching unauthorized modifications between maintenance windows.

Usage:
    # Save a baseline for a single device:
    python config_drift_detector.py --host 192.168.1.1 -u admin -p secret --save-baseline

    # Check drift against baseline:
    python config_drift_detector.py --host 192.168.1.1 -u admin -p secret --check-drift

    # Process multiple hosts (one IP/hostname per line, # for comments):
    python config_drift_detector.py --hosts-file devices.txt -u admin -p secret --check-drift

    # Save snapshot without baseline or drift check (archive only):
    python config_drift_detector.py --host 192.168.1.1 -u admin -p secret

Prerequisites:
    pip install netmiko
    Supported device types: cisco_ios, cisco_nxos, cisco_xr, arista_eos, juniper_junos
"""

import argparse
import difflib
import logging
import sys
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

SHOW_RUN_COMMANDS = {
    "cisco_ios": "show running-config",
    "cisco_nxos": "show running-config",
    "cisco_xr": "show running-config",
    "arista_eos": "show running-config",
    "juniper_junos": "show configuration | display set",
}

# Lines matching these prefixes change every run and pollute diffs
_VOLATILE_PREFIXES = (
    "! Last configuration change",
    "! NVRAM config last updated",
    "ntp clock-period",
)


def _strip_volatile(config_text):
    lines = [ln for ln in config_text.splitlines() if not ln.startswith(_VOLATILE_PREFIXES)]
    return "\n".join(lines)


def fetch_running_config(host, username, password, device_type, port, secret):
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "secret": secret or password,
    }
    conn = ConnectHandler(**params)
    try:
        cmd = SHOW_RUN_COMMANDS.get(device_type, "show running-config")
        raw = conn.send_command(cmd, read_timeout=60)
    finally:
        conn.disconnect()
    return _strip_volatile(raw)


def save_snapshot(snapshot_dir, host, config_text, is_baseline=False):
    device_dir = snapshot_dir / host
    device_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    snap = device_dir / f"{ts}.cfg"
    snap.write_text(config_text)
    log.info("Snapshot saved: %s", snap)

    if is_baseline:
        baseline = device_dir / "baseline.cfg"
        baseline.write_text(config_text)
        log.info("Baseline updated: %s", baseline)


def load_baseline(snapshot_dir, host):
    path = snapshot_dir / host / "baseline.cfg"
    if not path.exists():
        return None
    return path.read_text()


def report_drift(baseline, current, host):
    diff = list(difflib.unified_diff(
        baseline.splitlines(keepends=True),
        current.splitlines(keepends=True),
        fromfile=f"{host}/baseline",
        tofile=f"{host}/current",
        n=3,
    ))
    if diff:
        print(f"\n{'=' * 60}")
        print(f"DRIFT DETECTED: {host}")
        print(f"{'=' * 60}")
        print("".join(diff))
        return True
    log.info("No drift detected on %s", host)
    return False


def process_host(host, args, snapshot_dir):
    log.info("Connecting to %s (%s:%d)", host, args.device_type, args.port)
    try:
        config = fetch_running_config(
            host=host,
            username=args.username,
            password=args.password,
            device_type=args.device_type,
            port=args.port,
            secret=args.secret,
        )
    except NetmikoAuthenticationException:
        log.error("Authentication failed: %s", host)
        return False
    except NetmikoTimeoutException:
        log.error("Connection timed out: %s", host)
        return False
    except Exception as exc:
        log.error("Unexpected error on %s: %s", host, exc)
        return False

    save_snapshot(snapshot_dir, host, config, is_baseline=args.save_baseline)

    if args.check_drift:
        baseline = load_baseline(snapshot_dir, host)
        if baseline is None:
            log.warning("No baseline for %s — run with --save-baseline first", host)
        else:
            report_drift(baseline, config, host)

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Capture device configs and detect drift against a saved baseline."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--host", metavar="HOST", help="Single device IP or hostname")
    target.add_argument("--hosts-file", metavar="FILE", help="File listing devices, one per line")

    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument("--secret", default="", help="Enable secret (Cisco enable password)")
    parser.add_argument(
        "--device-type", default="cisco_ios", choices=list(SHOW_RUN_COMMANDS.keys())
    )
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument(
        "--save-baseline", action="store_true", help="Mark this snapshot as the drift baseline"
    )
    parser.add_argument(
        "--check-drift", action="store_true", help="Compare current config to baseline"
    )
    parser.add_argument(
        "--snapshot-dir", default="config_snapshots", help="Root directory for snapshots"
    )
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    snapshot_dir = Path(args.snapshot_dir)

    if args.host:
        hosts = [args.host]
    else:
        hosts_file = Path(args.hosts_file)
        if not hosts_file.exists():
            log.error("Hosts file not found: %s", args.hosts_file)
            sys.exit(1)
        hosts = [
            line.strip()
            for line in hosts_file.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]

    if not hosts:
        log.error("No hosts to process.")
        sys.exit(1)

    failures = sum(
        0 if process_host(h, args, snapshot_dir) else 1
        for h in hosts
    )

    log.info("Done — %d/%d succeeded.", len(hosts) - failures, len(hosts))
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
```