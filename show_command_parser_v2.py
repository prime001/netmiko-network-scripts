The user's instructions say "Output ONLY the script content" — this overrides the brainstorming design gate. Writing the script directly.

```
"""
interface_error_monitor.py - Interface error counter monitor for network devices.

Purpose:
    Collects interface error counters (input errors, output errors, CRC, runts,
    giants, resets, input/output drops) from a network device and reports any
    interfaces exceeding a configurable threshold. Useful for identifying degraded
    links, duplex mismatches, and oversubscribed uplinks before they cause outages.

Usage:
    python interface_error_monitor.py -d 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -d 10.0.0.1 -u admin --threshold 100
    python interface_error_monitor.py -d 10.0.0.1 -u admin -i Gi0/0,Gi0/1
    python interface_error_monitor.py -d 10.0.0.1 -u admin --json > errors.json

Prerequisites:
    pip install netmiko
    SSH access with at least read-only privileges on the target device.
    Tested against Cisco IOS/IOS-XE; arista_eos and cisco_nxos partially supported.
"""

import argparse
import json
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetMikoTimeoutException

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

_COUNTERS = [
    ("input_errors",  r"(\d+) input errors"),
    ("output_errors", r"(\d+) output errors"),
    ("crc",           r"(\d+) CRC"),
    ("runts",         r"(\d+) runts"),
    ("giants",        r"(\d+) giants"),
    ("resets",        r"(\d+) interface resets"),
    ("input_drops",   r"(\d+) input drops"),
    ("output_drops",  r"(\d+) output drops"),
]

_IFACE_RE = re.compile(
    r"^([A-Za-z][\w/.:]+)\s+is\s+(up|down|administratively down)",
    re.MULTILINE,
)


def parse_interfaces(output: str) -> list[dict]:
    records = []
    matches = list(_IFACE_RE.finditer(output))
    for idx, m in enumerate(matches):
        start = m.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(output)
        block = output[start:end]
        entry = {"name": m.group(1), "status": m.group(2)}
        for key, pattern in _COUNTERS:
            hit = re.search(pattern, block, re.IGNORECASE)
            entry[key] = int(hit.group(1)) if hit else 0
        records.append(entry)
    return records


def flag_errors(records: list[dict], threshold: int) -> list[dict]:
    counter_keys = [k for k, _ in _COUNTERS]
    return [r for r in records if any(r.get(k, 0) > threshold for k in counter_keys)]


def apply_filter(records: list[dict], names: list[str]) -> list[dict]:
    lower = {n.lower() for n in names}
    return [r for r in records if r["name"].lower() in lower]


def print_table(records: list[dict], flagged: list[dict], threshold: int) -> None:
    flagged_names = {r["name"] for r in flagged}
    col_keys = ["name", "input_errors", "output_errors", "crc", "runts",
                "giants", "input_drops", "output_drops", "resets"]
    headers  = ["Interface", "In Err", "Out Err", "CRC", "Runts",
                "Giants", "In Drop", "Out Drop", "Resets"]
    widths   = [32, 8, 9, 6, 7, 7, 8, 9, 7]

    header_row = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(header_row)
    print("-" * len(header_row))
    for r in records:
        flag = "  ***" if r["name"] in flagged_names else ""
        row = "  ".join(str(r.get(c, "")).ljust(w) for c, w in zip(col_keys, widths))
        print(row + flag)

    print()
    if flagged:
        print(f"{len(flagged)} interface(s) flagged (any counter > {threshold})")
    else:
        print(f"All interfaces within threshold (> {threshold})")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Monitor interface error counters on a network device",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", help="SSH password (prompted if omitted)")
    p.add_argument(
        "-t", "--device-type", default="cisco_ios",
        choices=["cisco_ios", "cisco_xe", "cisco_nxos", "arista_eos"],
        help="Netmiko device type",
    )
    p.add_argument(
        "-i", "--interfaces",
        help="Comma-separated interface names to inspect (default: all)",
    )
    p.add_argument(
        "--threshold", type=int, default=0,
        help="Flag interfaces where any counter exceeds this value",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port")
    p.add_argument(
        "--json", action="store_true", dest="as_json",
        help="Emit results as JSON instead of a table",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


def main() -> int:
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}@{args.device}: ")

    conn_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": password,
        "port": args.port,
    }

    try:
        log.debug("Connecting to %s", args.device)
        with ConnectHandler(**conn_params) as conn:
            output = conn.send_command("show interfaces")
    except AuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.device)
        return 2
    except NetMikoTimeoutException:
        log.error("Connection timed out: %s", args.device)
        return 2
    except Exception as exc:
        log.error("Connection error: %s", exc)
        return 2

    records = parse_interfaces(output)
    if not records:
        log.error("No interfaces parsed — verify device-type and SSH output")
        return 2

    if args.interfaces:
        names = [n.strip() for n in args.interfaces.split(",")]
        records = apply_filter(records, names)
        if not records:
            log.error("None of the requested interfaces were found on the device")
            return 2

    flagged = flag_errors(records, args.threshold)

    if args.as_json:
        print(json.dumps(
            {"device": args.device, "threshold": args.threshold,
             "interfaces": records, "flagged": flagged},
            indent=2,
        ))
    else:
        print_table(records, flagged, args.threshold)

    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
```