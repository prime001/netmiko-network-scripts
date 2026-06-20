```python
"""
interface_error_monitor.py — Interface Error Counter Monitor

Connects to a network device via SSH and audits interface error counters
(CRC, runts, giants, input/output errors, drops). Flags any interface
exceeding configurable thresholds and optionally writes JSON results for
downstream monitoring integration.

Usage:
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -d 10.0.0.1 -u admin -p secret \\
        --device-type cisco_ios --crc-threshold 10 --output errors.json

Prerequisites:
    pip install netmiko
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class InterfaceErrors:
    name: str
    crc: int = 0
    input_errors: int = 0
    output_errors: int = 0
    runts: int = 0
    giants: int = 0
    input_drops: int = 0
    output_drops: int = 0
    flagged: bool = False
    flags: list = field(default_factory=list)


def parse_ios_interface_errors(output: str) -> list[InterfaceErrors]:
    interfaces = []
    current: Optional[InterfaceErrors] = None

    intf_re = re.compile(r"^(\S+) is ")
    crc_re = re.compile(r"(\d+) CRC")
    input_err_re = re.compile(r"(\d+) input errors")
    output_err_re = re.compile(r"(\d+) output errors")
    runts_re = re.compile(r"(\d+) runts")
    giants_re = re.compile(r"(\d+) giants")
    in_drop_re = re.compile(r"(\d+) input drops", re.IGNORECASE)
    out_drop_re = re.compile(r"(\d+) output drops", re.IGNORECASE)

    for line in output.splitlines():
        m = intf_re.match(line)
        if m:
            if current:
                interfaces.append(current)
            current = InterfaceErrors(name=m.group(1))
            continue
        if current is None:
            continue
        for pattern, attr in [
            (crc_re, "crc"),
            (input_err_re, "input_errors"),
            (output_err_re, "output_errors"),
            (runts_re, "runts"),
            (giants_re, "giants"),
            (in_drop_re, "input_drops"),
            (out_drop_re, "output_drops"),
        ]:
            hit = pattern.search(line)
            if hit:
                setattr(current, attr, int(hit.group(1)))

    if current:
        interfaces.append(current)
    return interfaces


def apply_thresholds(
    interfaces: list[InterfaceErrors],
    crc_thresh: int,
    error_thresh: int,
    drop_thresh: int,
) -> list[InterfaceErrors]:
    for intf in interfaces:
        if intf.crc >= crc_thresh:
            intf.flags.append(f"CRC={intf.crc} >= {crc_thresh}")
        if intf.input_errors >= error_thresh:
            intf.flags.append(f"input_errors={intf.input_errors} >= {error_thresh}")
        if intf.output_errors >= error_thresh:
            intf.flags.append(f"output_errors={intf.output_errors} >= {error_thresh}")
        if intf.input_drops + intf.output_drops >= drop_thresh:
            total = intf.input_drops + intf.output_drops
            intf.flags.append(f"drops={total} >= {drop_thresh}")
        intf.flagged = bool(intf.flags)
    return interfaces


def check_device(
    host: str,
    username: str,
    password: str,
    device_type: str,
    port: int,
    crc_thresh: int,
    error_thresh: int,
    drop_thresh: int,
) -> list[InterfaceErrors]:
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
    }
    log.info("Connecting to %s (%s)", host, device_type)
    with ConnectHandler(**device) as conn:
        output = conn.send_command("show interfaces", read_timeout=60)
    log.info("Parsing interface error counters")
    interfaces = parse_ios_interface_errors(output)
    return apply_thresholds(interfaces, crc_thresh, error_thresh, drop_thresh)


def print_report(host: str, interfaces: list[InterfaceErrors]) -> int:
    flagged = [i for i in interfaces if i.flagged]
    print(f"\nInterface Error Report — {host}")
    print(f"  Checked : {len(interfaces)} interfaces")
    print(f"  Flagged : {len(flagged)}\n")
    if not flagged:
        print("  All interfaces within thresholds.")
        return 0
    for intf in flagged:
        print(f"  [WARN] {intf.name}")
        for flag in intf.flags:
            print(f"         {flag}")
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Audit interface error counters on a network device."
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)
    p.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)"
    )
    p.add_argument("--port", type=int, default=22)
    p.add_argument(
        "--crc-threshold", type=int, default=5,
        help="CRC errors per interface to flag (default: 5)"
    )
    p.add_argument(
        "--error-threshold", type=int, default=10,
        help="Input/output errors per interface to flag (default: 10)"
    )
    p.add_argument(
        "--drop-threshold", type=int, default=100,
        help="Combined drops per interface to flag (default: 100)"
    )
    p.add_argument(
        "--output", metavar="FILE",
        help="Write JSON results to FILE"
    )
    p.add_argument("--verbose", action="store_true")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        results = check_device(
            host=args.device,
            username=args.username,
            password=args.password,
            device_type=args.device_type,
            port=args.port,
            crc_thresh=args.crc_threshold,
            error_thresh=args.error_threshold,
            drop_thresh=args.drop_threshold,
        )
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.device)
        sys.exit(2)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.device)
        sys.exit(2)
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        sys.exit(2)

    exit_code = print_report(args.device, results)

    if args.output:
        payload = {
            "device": args.device,
            "interfaces": [asdict(i) for i in results],
        }
        with open(args.output, "w") as fh:
            json.dump(payload, fh, indent=2)
        log.info("Results written to %s", args.output)

    sys.exit(exit_code)
```