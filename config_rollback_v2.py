```python
"""
interface_error_monitor.py — Network interface error counter monitor.

Purpose:
    Connects to Cisco IOS/IOS-XE devices via SSH and collects per-interface
    error statistics: input errors, output errors, CRC, runts, giants, and drops.
    Flags any interface whose combined error count exceeds a configurable threshold.

    With --poll 2, takes two snapshots separated by --interval seconds and reports
    the *delta*, catching actively-degrading links rather than stale historic counters.

Usage:
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret \\
        --poll 2 --interval 60 --threshold 10 --output errors.json

Prerequisites:
    pip install netmiko
"""

import argparse
import json
import logging
import re
import time
from dataclasses import asdict, dataclass

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class InterfaceErrors:
    name: str
    input_errors: int = 0
    output_errors: int = 0
    crc: int = 0
    input_drops: int = 0
    output_drops: int = 0
    runts: int = 0
    giants: int = 0


def parse_interface_errors(output: str) -> dict[str, InterfaceErrors]:
    """Parse 'show interfaces' output into per-interface error counters."""
    interfaces: dict[str, InterfaceErrors] = {}
    current: InterfaceErrors | None = None

    for line in output.splitlines():
        iface_match = re.match(r"^(\S+) is (?:up|down|administratively down)", line)
        if iface_match:
            current = InterfaceErrors(name=iface_match.group(1))
            interfaces[current.name] = current
            continue

        if current is None:
            continue

        if m := re.search(r"(\d+) input errors", line):
            current.input_errors = int(m.group(1))
        if m := re.search(r"(\d+) CRC", line):
            current.crc = int(m.group(1))
        if m := re.search(r"(\d+) output errors", line):
            current.output_errors = int(m.group(1))
        if m := re.search(r"(\d+) input drops", line):
            current.input_drops = int(m.group(1))
        if m := re.search(r"(\d+) output drops", line):
            current.output_drops = int(m.group(1))
        if m := re.search(r"(\d+) runts", line):
            current.runts = int(m.group(1))
        if m := re.search(r"(\d+) giants", line):
            current.giants = int(m.group(1))

    return interfaces


def total_errors(iface: InterfaceErrors) -> int:
    return (
        iface.input_errors + iface.output_errors + iface.crc
        + iface.input_drops + iface.output_drops + iface.runts + iface.giants
    )


def compute_delta(first: InterfaceErrors, second: InterfaceErrors) -> InterfaceErrors:
    return InterfaceErrors(
        name=first.name,
        input_errors=second.input_errors - first.input_errors,
        output_errors=second.output_errors - first.output_errors,
        crc=second.crc - first.crc,
        input_drops=second.input_drops - first.input_drops,
        output_drops=second.output_drops - first.output_drops,
        runts=second.runts - first.runts,
        giants=second.giants - first.giants,
    )


def check_device(
    host: str,
    username: str,
    password: str,
    device_type: str = "cisco_ios",
    poll_count: int = 1,
    poll_interval: int = 60,
    threshold: int = 0,
) -> dict:
    result: dict = {"host": host, "polls": [], "flagged": [], "error": None}

    try:
        log.info("Connecting to %s", host)
        with ConnectHandler(
            device_type=device_type, host=host,
            username=username, password=password,
        ) as conn:
            polls: list[dict[str, InterfaceErrors]] = []

            for i in range(poll_count):
                if i > 0:
                    log.info("Waiting %ds before poll %d/%d", poll_interval, i + 1, poll_count)
                    time.sleep(poll_interval)
                log.info("Poll %d/%d on %s", i + 1, poll_count, host)
                snap = parse_interface_errors(conn.send_command("show interfaces"))
                polls.append(snap)
                result["polls"].append({k: asdict(v) for k, v in snap.items()})

            if len(polls) == 2:
                evaluated = {
                    name: compute_delta(polls[0][name], polls[1][name])
                    for name in polls[0]
                    if name in polls[1]
                }
                log.info("Using %ds error deltas", poll_interval)
            else:
                evaluated = polls[0]

            for name, iface in evaluated.items():
                tot = total_errors(iface)
                if tot > threshold:
                    result["flagged"].append(asdict(iface))
                    log.warning(
                        "%-30s total=%d  in_err=%d  crc=%d  out_err=%d  drops=%d/%d",
                        name, tot, iface.input_errors, iface.crc, iface.output_errors,
                        iface.input_drops, iface.output_drops,
                    )

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", host)
        result["error"] = "authentication_failed"
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", host)
        result["error"] = "timeout"
    except Exception as exc:
        log.error("Unexpected error on %s: %s", host, exc)
        result["error"] = str(exc)

    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Monitor network interface error counters via SSH using netmiko."
    )
    parser.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument(
        "--poll", type=int, default=1, choices=[1, 2],
        help="Poll count: 1=absolute counters, 2=delta over --interval seconds",
    )
    parser.add_argument(
        "--interval", type=int, default=60,
        help="Seconds between polls when --poll 2 (default: 60)",
    )
    parser.add_argument(
        "--threshold", type=int, default=0,
        help="Flag interfaces with combined error count above this value (default: 0)",
    )
    parser.add_argument("--output", metavar="FILE", help="Write JSON results to FILE")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    result = check_device(
        host=args.device,
        username=args.username,
        password=args.password,
        device_type=args.device_type,
        poll_count=args.poll,
        poll_interval=args.interval,
        threshold=args.threshold,
    )

    flagged = result.get("flagged", [])
    if result.get("error"):
        print(f"ERROR: {result['error']}")
    elif flagged:
        print(f"\n{len(flagged)} interface(s) exceeded threshold ({args.threshold}):")
        for iface in flagged:
            tot = (iface["input_errors"] + iface["output_errors"] + iface["crc"]
                   + iface["input_drops"] + iface["output_drops"]
                   + iface["runts"] + iface["giants"])
            print(f"  {iface['name']:<30} total={tot:>6}  "
                  f"in_err={iface['input_errors']}  crc={iface['crc']}  "
                  f"out_err={iface['output_errors']}")
    else:
        print(f"All interfaces within threshold ({args.threshold}).")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(result, fh, indent=2)
        log.info("Results written to %s", args.output)
```