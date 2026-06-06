```python
"""
interface_error_monitor.py - Monitor interface error counters on network devices.

Purpose:
    Connects to a network device via SSH and inspects interface error counters
    (input errors, output errors, CRC, giants, runts). Flags any interface whose
    counters exceed configurable thresholds. Useful for scheduled NOC checks or
    post-incident audits across Cisco IOS/IOS-XE/NX-OS and Juniper JunOS devices.

Usage:
    python interface_error_monitor.py -H 192.168.1.1 -u admin -p secret
    python interface_error_monitor.py -H 10.0.0.1 -u admin -p secret \\
        --device-type cisco_nxos --crc-threshold 50 --error-threshold 100
    python interface_error_monitor.py -H 10.0.0.1 -u admin -p secret \\
        --interfaces Gi0/1 Gi0/2 --output results.json

Prerequisites:
    pip install netmiko
    SSH must be enabled; account needs at minimum read-only (show) privileges.
    Supported device types: cisco_ios, cisco_xe, cisco_nxos, juniper_junos
"""

import argparse
import json
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)

VENDOR_CONFIG = {
    "cisco_ios": {
        "command": "show interfaces",
        "iface_re": re.compile(r"^(\S+)\s+is\s+(?:up|down|administratively down)", re.M),
        "counters_re": re.compile(
            r"(\d+) input errors.*?(\d+) CRC.*?(\d+) giants.*?(\d+) runts.*?(\d+) output errors",
            re.DOTALL,
        ),
    },
    "cisco_xe": {
        "command": "show interfaces",
        "iface_re": re.compile(r"^(\S+)\s+is\s+(?:up|down|administratively down)", re.M),
        "counters_re": re.compile(
            r"(\d+) input errors.*?(\d+) CRC.*?(\d+) giants.*?(\d+) runts.*?(\d+) output errors",
            re.DOTALL,
        ),
    },
    "cisco_nxos": {
        "command": "show interface",
        "iface_re": re.compile(r"^(\S+)\s+is\s+(?:up|down|administratively down)", re.M),
        "counters_re": re.compile(
            r"(\d+) input error.*?(\d+) CRC.*?(\d+) giant.*?(\d+) runt.*?(\d+) output error",
            re.DOTALL,
        ),
    },
    "juniper_junos": {
        "command": "show interfaces detail",
        "iface_re": re.compile(r"^Physical interface:\s+(\S+)", re.M),
        "counters_re": re.compile(
            r"Input errors:\s+(\d+).*?Framing errors:\s+(\d+).*?"
            r"Giant frames:\s+(\d+).*?Runts:\s+(\d+).*?Output errors:\s+(\d+)",
            re.DOTALL,
        ),
    },
}


def split_interface_blocks(output, vendor):
    iface_re = VENDOR_CONFIG[vendor]["iface_re"]
    matches = list(iface_re.finditer(output))
    blocks = {}
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(output)
        blocks[m.group(1)] = output[m.start():end]
    return blocks


def extract_counters(block, vendor):
    m = VENDOR_CONFIG[vendor]["counters_re"].search(block)
    if not m:
        return None
    vals = [int(x) for x in m.groups()]
    return {
        "input_errors": vals[0],
        "crc_errors": vals[1],
        "giants": vals[2],
        "runts": vals[3],
        "output_errors": vals[4],
    }


def find_violations(counters, error_threshold, crc_threshold):
    checks = [
        ("input_errors", counters["input_errors"], error_threshold),
        ("output_errors", counters["output_errors"], error_threshold),
        ("crc_errors", counters["crc_errors"], crc_threshold),
    ]
    return [(f, v, t) for f, v, t in checks if v > t]


def run(args):
    if args.device_type not in VENDOR_CONFIG:
        log.error("Unsupported device type: %s", args.device_type)
        return 1

    log.info("Connecting to %s (%s)", args.host, args.device_type)
    try:
        conn = ConnectHandler(
            device_type=args.device_type,
            host=args.host,
            username=args.username,
            password=args.password,
            port=args.port,
            timeout=args.timeout,
        )
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except NetmikoTimeoutException:
        log.error("Connection timed out: %s", args.host)
        return 1

    cmd = VENDOR_CONFIG[args.device_type]["command"]
    log.info("Running: %s", cmd)
    output = conn.send_command(cmd)
    conn.disconnect()

    blocks = split_interface_blocks(output, args.device_type)
    if args.interfaces:
        blocks = {k: v for k, v in blocks.items() if k in args.interfaces}

    results = {}
    flagged = 0

    for iface, block in blocks.items():
        counters = extract_counters(block, args.device_type)
        if counters is None:
            log.debug("No counter data parsed for %s, skipping", iface)
            continue

        violations = find_violations(counters, args.error_threshold, args.crc_threshold)
        results[iface] = {
            "counters": counters,
            "violations": [{"field": f, "value": v, "threshold": t} for f, v, t in violations],
        }

        if violations:
            flagged += 1
            detail = ", ".join(f"{f}={v} (>{t})" for f, v, t in violations)
            log.warning("THRESHOLD EXCEEDED  %-30s  %s", iface, detail)
        else:
            log.info("OK  %s", iface)

    log.info("Checked %d interface(s); %d flagged.", len(results), flagged)

    payload = json.dumps(results, indent=2)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(payload)
        log.info("Results written to %s", args.output)
    else:
        print(payload)

    return 1 if flagged else 0


def build_parser():
    p = argparse.ArgumentParser(
        description="Monitor interface error counters and alert on threshold violations."
    )
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", default=None, help="SSH password (prompted if omitted)")
    p.add_argument(
        "-t", "--device-type",
        dest="device_type",
        default="cisco_ios",
        choices=list(VENDOR_CONFIG.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=30, help="Connection timeout seconds (default: 30)")
    p.add_argument(
        "--interfaces", nargs="+", metavar="INTF",
        help="Limit check to named interfaces, e.g. --interfaces Gi0/1 Gi0/2",
    )
    p.add_argument(
        "--error-threshold", type=int, default=0,
        help="Alert when input/output error count exceeds this (default: 0)",
    )
    p.add_argument(
        "--crc-threshold", type=int, default=0,
        help="Alert when CRC error count exceeds this (default: 0)",
    )
    p.add_argument("-o", "--output", metavar="FILE", help="Write JSON results to FILE instead of stdout")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.password is None:
        args.password = getpass(f"Password for {args.username}@{args.host}: ")

    sys.exit(run(args))
```