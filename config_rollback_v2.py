The output is the script content itself:

```python
"""
interface_error_monitor.py - Interface Error Rate Monitor

Connects to a Cisco IOS/IOS-XE device via SSH, samples interface error counters
twice across a configurable interval, calculates per-second error rates, and
reports any interface exceeding defined thresholds.

Useful for post-change validation, overnight baselining, or triage when users
report intermittent packet loss without a clear fault source.

Usage:
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret \\
        --device-type cisco_ios --interval 60 --samples 3 \\
        --in-err-threshold 5 --out-err-threshold 5 --crc-threshold 1

Prerequisites:
    pip install netmiko
    SSH must be enabled on the target device.
    Credentials require at minimum privilege-1 (show access).
"""

import argparse
import logging
import re
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


@dataclass
class InterfaceCounters:
    name: str
    input_errors: int = 0
    output_errors: int = 0
    crc: int = 0
    input_drops: int = 0
    output_drops: int = 0


def parse_show_interfaces(output: str) -> Dict[str, InterfaceCounters]:
    """Parse 'show interfaces' output into per-interface counter snapshots."""
    counters: Dict[str, InterfaceCounters] = {}
    current: Optional[str] = None

    iface_re = re.compile(r"^(\S+) is (?:up|down|administratively down)")
    in_err_re = re.compile(r"(\d+) input errors.*?(\d+) CRC", re.IGNORECASE)
    out_err_re = re.compile(r"(\d+) output errors", re.IGNORECASE)
    in_drop_re = re.compile(r"Input queue: \d+/\d+/(\d+)/", re.IGNORECASE)
    out_drop_re = re.compile(r"Total output drops: (\d+)", re.IGNORECASE)

    for line in output.splitlines():
        m = iface_re.match(line)
        if m:
            current = m.group(1)
            counters[current] = InterfaceCounters(name=current)
            continue

        if current is None:
            continue

        m = in_err_re.search(line)
        if m:
            counters[current].input_errors = int(m.group(1))
            counters[current].crc = int(m.group(2))
            continue

        m = out_err_re.search(line)
        if m:
            counters[current].output_errors = int(m.group(1))
            continue

        m = in_drop_re.search(line)
        if m:
            counters[current].input_drops = int(m.group(1))
            continue

        m = out_drop_re.search(line)
        if m:
            counters[current].output_drops = int(m.group(1))

    return counters


def delta_rate(before: int, after: int, elapsed: float) -> float:
    """Return per-second rate, treating counter wraps as zero-delta."""
    diff = after - before
    if diff < 0:
        return 0.0
    return diff / elapsed if elapsed > 0 else 0.0


def collect_samples(
    connection,
    samples: int,
    interval: float,
) -> List[Tuple[float, Dict[str, InterfaceCounters]]]:
    """Collect multiple counter snapshots separated by interval seconds."""
    snapshots = []
    for i in range(samples):
        if i > 0:
            logger.info("Waiting %ds before next sample (%d/%d)...", int(interval), i + 1, samples)
            time.sleep(interval)
        ts = time.monotonic()
        raw = connection.send_command("show interfaces", read_timeout=60)
        snapshot = parse_show_interfaces(raw)
        snapshots.append((ts, snapshot))
        logger.info("Sample %d collected — %d interfaces parsed", i + 1, len(snapshot))
    return snapshots


def analyze(
    snapshots: List[Tuple[float, Dict[str, InterfaceCounters]]],
    in_err_threshold: float,
    out_err_threshold: float,
    crc_threshold: float,
) -> List[dict]:
    """Compare first and last snapshots; return flagged interfaces."""
    if len(snapshots) < 2:
        logger.warning("Need at least 2 samples to compute rates; skipping analysis.")
        return []

    t0, snap0 = snapshots[0]
    t1, snap1 = snapshots[-1]
    elapsed = t1 - t0

    flagged = []
    for iface, after in snap1.items():
        before = snap0.get(iface)
        if before is None:
            continue

        rates = {
            "in_err_rate": delta_rate(before.input_errors, after.input_errors, elapsed),
            "out_err_rate": delta_rate(before.output_errors, after.output_errors, elapsed),
            "crc_rate": delta_rate(before.crc, after.crc, elapsed),
            "in_drop_rate": delta_rate(before.input_drops, after.input_drops, elapsed),
            "out_drop_rate": delta_rate(before.output_drops, after.output_drops, elapsed),
        }

        breached = (
            rates["in_err_rate"] > in_err_threshold
            or rates["out_err_rate"] > out_err_threshold
            or rates["crc_rate"] > crc_threshold
        )

        if breached:
            flagged.append({"interface": iface, "elapsed_s": round(elapsed, 1), **rates})

    return flagged


def print_report(host: str, flagged: List[dict]) -> None:
    if not flagged:
        print(f"\n[OK] {host}: no interfaces exceeded error thresholds.")
        return

    print(f"\n[ALERT] {host}: {len(flagged)} interface(s) exceeded thresholds:\n")
    header = f"  {'Interface':<30} {'InErr/s':>8} {'OutErr/s':>9} {'CRC/s':>7} {'InDrop/s':>9} {'OutDrop/s':>10}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for r in sorted(flagged, key=lambda x: x["interface"]):
        print(
            f"  {r['interface']:<30} {r['in_err_rate']:>8.3f} {r['out_err_rate']:>9.3f} "
            f"{r['crc_rate']:>7.3f} {r['in_drop_rate']:>9.3f} {r['out_drop_rate']:>10.3f}"
        )
    print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sample interface error counters and report rates exceeding thresholds.",
    )
    parser.add_argument("-H", "--host", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument("--enable-secret", default=None, help="Enable/secret password if needed")
    parser.add_argument("--device-type", default="cisco_ios", help="Netmiko device type (default: cisco_ios)")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--interval", type=float, default=30.0, help="Seconds between samples (default: 30)")
    parser.add_argument("--samples", type=int, default=2, help="Number of samples to collect (default: 2)")
    parser.add_argument("--in-err-threshold", type=float, default=1.0, dest="in_err_threshold",
                        help="Input error rate (per-sec) to flag (default: 1.0)")
    parser.add_argument("--out-err-threshold", type=float, default=1.0, dest="out_err_threshold",
                        help="Output error rate (per-sec) to flag (default: 1.0)")
    parser.add_argument("--crc-threshold", type=float, default=0.1, dest="crc_threshold",
                        help="CRC error rate (per-sec) to flag (default: 0.1)")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }
    if args.enable_secret:
        device["secret"] = args.enable_secret

    logger.info("Connecting to %s (%s)...", args.host, args.device_type)
    try:
        with ConnectHandler(**device) as conn:
            if args.enable_secret:
                conn.enable()
            logger.info("Connected. Collecting %d sample(s) with %ds interval.", args.samples, int(args.interval))
            snapshots = collect_samples(conn, args.samples, args.interval)
    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        logger.error("Connection timed out reaching %s", args.host)
        sys.exit(1)
    except Exception as exc:
        logger.error("Unexpected error: %s", exc)
        sys.exit(1)

    flagged = analyze(snapshots, args.in_err_threshold, args.out_err_threshold, args.crc_threshold)
    print_report(args.host, flagged)
    sys.exit(1 if flagged else 0)
```