```python
"""
interface_error_monitor.py - Delta-based interface error rate monitor.

Connects to a network device, samples 'show interfaces' counters twice across a
configurable interval, computes per-interface error rates, and flags any that
exceed the specified threshold.  Exits non-zero when flagged interfaces exist so
the script integrates cleanly with Nagios/NRPE, cron, or CI pipelines.

Usage:
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -d 10.0.0.1 -u admin -p secret \\
        --device-type cisco_ios --interval 30 --threshold 0.5 --json

Prerequisites:
    pip install netmiko
    SSH access to the device with credentials that allow 'show interfaces'.
"""

import argparse
import json
import logging
import re
import sys
import time
from typing import Dict

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logger = logging.getLogger(__name__)


def parse_show_interfaces(output: str) -> Dict[str, Dict[str, int]]:
    counters: Dict[str, Dict[str, int]] = {}
    current = None

    for line in output.splitlines():
        m = re.match(r'^(\S+)\s+is\s+(?:up|down|administratively down)', line, re.IGNORECASE)
        if m:
            current = m.group(1)
            counters[current] = {"input_errors": 0, "output_errors": 0, "crc": 0, "drops": 0}
            continue

        if current is None:
            continue

        m = re.search(r'(\d+) input errors', line)
        if m:
            counters[current]["input_errors"] = int(m.group(1))

        m = re.search(r'(\d+) CRC', line)
        if m:
            counters[current]["crc"] = int(m.group(1))

        m = re.search(r'(\d+) output errors', line)
        if m:
            counters[current]["output_errors"] = int(m.group(1))

        m = re.search(r'(\d+)\s+(?:input drops|drops)', line)
        if m:
            counters[current]["drops"] = int(m.group(1))

    return counters


def compute_deltas(
    t1: Dict[str, Dict[str, int]],
    t2: Dict[str, Dict[str, int]],
    interval: float,
    threshold: float,
) -> list:
    rows = []
    for intf, c2 in t2.items():
        if intf not in t1:
            continue
        c1 = t1[intf]
        d_in = max(0, c2["input_errors"] - c1["input_errors"])
        d_out = max(0, c2["output_errors"] - c1["output_errors"])
        d_crc = max(0, c2["crc"] - c1["crc"])
        d_drop = max(0, c2["drops"] - c1["drops"])
        rate = (d_in + d_out + d_crc) / interval if interval > 0 else 0.0
        rows.append({
            "interface": intf,
            "input_errors_delta": d_in,
            "output_errors_delta": d_out,
            "crc_delta": d_crc,
            "drops_delta": d_drop,
            "errors_per_sec": round(rate, 4),
            "flagged": rate > threshold,
        })
    return sorted(rows, key=lambda r: r["errors_per_sec"], reverse=True)


def build_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sample interface error counters twice and report delta rates."
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("--device-type", default="cisco_ios",
                   help="Netmiko device type (default: cisco_ios)")
    p.add_argument("--interval", type=float, default=60.0,
                   help="Seconds between samples (default: 60)")
    p.add_argument("--threshold", type=float, default=1.0,
                   help="Errors/sec that triggers a flag (default: 1.0)")
    p.add_argument("--timeout", type=int, default=30,
                   help="SSH timeout in seconds (default: 30)")
    p.add_argument("--json", action="store_true", help="Emit JSON output")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return p.parse_args()


def main() -> int:
    args = build_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    conn_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "timeout": args.timeout,
        "fast_cli": False,
    }

    try:
        with ConnectHandler(**conn_params) as conn:
            logger.debug("T1 sample on %s", args.device)
            t1 = parse_show_interfaces(conn.send_command("show interfaces"))

            if not args.json:
                print(f"Sampling {len(t1)} interfaces — waiting {args.interval}s ...")

            time.sleep(args.interval)

            logger.debug("T2 sample on %s", args.device)
            t2 = parse_show_interfaces(conn.send_command("show interfaces"))

    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.device)
        return 2
    except NetmikoTimeoutException:
        logger.error("Connection timed out to %s", args.device)
        return 3
    except Exception as exc:
        logger.error("Unexpected error: %s", exc)
        return 1

    results = compute_deltas(t1, t2, args.interval, args.threshold)
    flagged_count = sum(1 for r in results if r["flagged"])

    if args.json:
        print(json.dumps({
            "device": args.device,
            "interval_sec": args.interval,
            "threshold_errors_per_sec": args.threshold,
            "interfaces": results,
        }, indent=2))
    else:
        header = f"{'Interface':<32} {'InErr':>7} {'OutErr':>7} {'CRC':>6} {'Drops':>7} {'Err/s':>9}"
        print(f"\n{header}")
        print("-" * len(header))
        for r in results:
            flag = " !" if r["flagged"] else ""
            print(
                f"{r['interface']:<32} {r['input_errors_delta']:>7} "
                f"{r['output_errors_delta']:>7} {r['crc_delta']:>6} "
                f"{r['drops_delta']:>7} {r['errors_per_sec']:>9.4f}{flag}"
            )
        status = "FLAGGED" if flagged_count else "OK"
        print(f"\n[{status}] {flagged_count} interface(s) exceeded {args.threshold} errors/sec")

    return 1 if flagged_count else 0


if __name__ == "__main__":
    sys.exit(main())
```