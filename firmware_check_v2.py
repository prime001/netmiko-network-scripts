```python
"""
firmware_prestage.py - Firmware upgrade pre-staging readiness checker.

Purpose:
    Verifies that a target firmware image is present on device flash and that
    sufficient free space exists before a maintenance window begins. Complements
    firmware_check.py (which validates running versions) by focusing on whether
    devices are ready to execute an upgrade, not whether an upgrade is needed.

Usage:
    Single device:
        python firmware_prestage.py -d 192.168.1.1 -u admin -p secret \
            --target-image c2960x-universalk9-mz.152-7.E2.bin

    Batch from file (one IP or hostname per line, # for comments):
        python firmware_prestage.py --host-file switches.txt -u admin \
            --target-image c2960x-universalk9-mz.152-7.E2.bin --min-free-mb 128

    Exit code 0 = all devices READY, 1 = one or more not ready.

Prerequisites:
    pip install netmiko
"""

import argparse
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def parse_dir_output(output):
    """Return (free_bytes, [filenames]) from 'dir flash:' output."""
    files = []
    free_bytes = 0
    for line in output.splitlines():
        # File entry lines start with whitespace + numeric index
        if re.match(r"^\s+\d+\s", line):
            parts = line.split()
            if parts:
                files.append(parts[-1])
        free_match = re.search(r"(\d+)\s+bytes\s+available", line)
        if free_match:
            free_bytes = int(free_match.group(1))
    return free_bytes, files


def check_device(host, device_type, username, password, target_image, min_free_bytes):
    """Connect to a single device and return a readiness result dict."""
    result = {
        "host": host,
        "status": "UNKNOWN",
        "image_present": False,
        "free_mb": None,
        "error": None,
    }

    try:
        log.info("Connecting to %s", host)
        with ConnectHandler(
            device_type=device_type,
            host=host,
            username=username,
            password=password,
            timeout=30,
        ) as conn:
            output = conn.send_command("dir flash:", read_timeout=30)
            free_bytes, files = parse_dir_output(output)

            result["free_mb"] = round(free_bytes / 1024 / 1024, 1)
            result["image_present"] = target_image in files
            space_ok = free_bytes >= min_free_bytes

            if result["image_present"] and space_ok:
                result["status"] = "READY"
            elif result["image_present"]:
                result["status"] = "WARN_LOW_SPACE"
            elif space_ok:
                result["status"] = "NEEDS_TRANSFER"
            else:
                result["status"] = "NOT_READY"

    except NetmikoAuthenticationException:
        result["status"] = "AUTH_FAILED"
        result["error"] = "Authentication failed"
        log.error("Auth failed: %s", host)
    except NetmikoTimeoutException:
        result["status"] = "TIMEOUT"
        result["error"] = "Connection timed out"
        log.error("Timeout: %s", host)
    except Exception as exc:
        result["status"] = "ERROR"
        result["error"] = str(exc)
        log.error("Error on %s: %s", host, exc)

    return result


def print_report(results, target_image, min_free_mb):
    width = 72
    print(f"\n{'=' * width}")
    print("Firmware Pre-staging Readiness Report")
    print(f"  Target image : {target_image}")
    print(f"  Min free     : {min_free_mb} MB")
    print(f"{'=' * width}")
    print(f"{'Host':<22} {'Status':<18} {'Image':<8} {'Free MB'}")
    print(f"{'-' * width}")

    counts = {}
    for r in results:
        img = "YES" if r["image_present"] else "NO"
        free = f"{r['free_mb']}" if r["free_mb"] is not None else "N/A"
        note = f"  [{r['error']}]" if r["error"] else ""
        print(f"{r['host']:<22} {r['status']:<18} {img:<8} {free}{note}")
        counts[r["status"]] = counts.get(r["status"], 0) + 1

    print(f"{'=' * width}")
    for status, n in sorted(counts.items()):
        print(f"  {status}: {n}")
    print()


def load_hosts(path):
    with open(path) as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]


def main():
    parser = argparse.ArgumentParser(
        description="Check firmware pre-staging readiness on network devices"
    )
    host_group = parser.add_mutually_exclusive_group(required=True)
    host_group.add_argument("-d", "--device", help="Single device IP or hostname")
    host_group.add_argument(
        "--host-file", help="File containing one device per line"
    )
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", help="Prompted if omitted")
    parser.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)"
    )
    parser.add_argument(
        "--target-image", required=True,
        help="Firmware filename to look for (e.g. c2960x-universalk9-mz.152-7.E2.bin)"
    )
    parser.add_argument(
        "--min-free-mb", type=int, default=64,
        help="Minimum acceptable free flash in MB (default: 64)"
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}: ")

    hosts = [args.device] if args.device else load_hosts(args.host_file)
    if not hosts:
        log.error("No hosts found")
        sys.exit(1)

    min_free_bytes = args.min_free_mb * 1024 * 1024
    results = [
        check_device(
            h, args.device_type, args.username, password,
            args.target_image, min_free_bytes
        )
        for h in hosts
    ]

    print_report(results, args.target_image, args.min_free_mb)

    not_ready = [r for r in results if r["status"] != "READY"]
    sys.exit(0 if not not_ready else 1)


if __name__ == "__main__":
    main()
```