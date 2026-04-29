The existing scripts are named in the prompt but not in this repo — I have enough context to write something non-duplicate. Here's the script:

```python
"""
005_multi_vendor_runner.py — Concurrent multi-vendor show-command runner.

Connects to every device in an inventory CSV simultaneously and executes one
or more show commands.  Results are printed to stdout and optionally saved as
per-device text files.  Vendor detection is automatic via Netmiko's
device_type field (cisco_ios, cisco_nxos, arista_eos, juniper_junos, etc.).

Usage
-----
    # Single command across all devices
    python 005_multi_vendor_runner.py \
        --inventory inventory.csv --command "show version"

    # Multiple commands, save output files, 10 parallel workers
    python 005_multi_vendor_runner.py \
        --inventory inventory.csv \
        --commands "show interfaces status" "show ip route summary" \
        --output-dir ./results --workers 10

    # Override credentials at runtime instead of storing in CSV
    python 005_multi_vendor_runner.py \
        --inventory inventory.csv --command "show version" \
        --username admin --password secret

Inventory CSV format (header row required)
------------------------------------------
    hostname,device_type,host,port,username,password,secret
    core-rtr-01,cisco_ios,10.0.0.1,22,admin,mypass,enable123
    dist-sw-01,arista_eos,10.0.0.2,22,admin,mypass,

    port and secret are optional (defaults: 22, empty disables enable).
    password and secret may be omitted from the CSV and supplied via CLI
    flags to avoid storing credentials in plain text.

Prerequisites
-------------
    pip install netmiko
    Python >= 3.9
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def load_inventory(
    csv_path: str,
    default_username: str = "",
    default_password: str = "",
    default_secret: str = "",
) -> list[dict]:
    devices = []
    with open(csv_path, newline="") as fh:
        for row in csv.DictReader(fh):
            device = {
                "host": row["host"].strip(),
                "device_type": row["device_type"].strip(),
                "username": (row.get("username") or default_username).strip(),
                "password": (row.get("password") or default_password).strip(),
                "port": int(row.get("port") or 22),
                "secret": (row.get("secret") or default_secret).strip(),
                "_hostname": row.get("hostname", row["host"]).strip(),
            }
            if not device["username"]:
                raise ValueError(
                    f"No username for {device['_hostname']} — "
                    "supply via CSV column or --username flag"
                )
            devices.append(device)
    return devices


def run_commands(device: dict, commands: list[str]) -> dict:
    hostname = device.pop("_hostname")
    result: dict = {"hostname": hostname, "host": device["host"], "outputs": {}, "error": None}
    try:
        log.info("Connecting  →  %s  (%s)", hostname, device["host"])
        with ConnectHandler(**device) as conn:
            if device.get("secret"):
                conn.enable()
            for cmd in commands:
                result["outputs"][cmd] = conn.send_command(cmd, read_timeout=30)
        log.info("Done        ←  %s", hostname)
    except NetmikoAuthenticationException as exc:
        result["error"] = f"Auth failed: {exc}"
        log.warning("%s — authentication error", hostname)
    except NetmikoTimeoutException as exc:
        result["error"] = f"Timeout: {exc}"
        log.warning("%s — connection timed out", hostname)
    except Exception as exc:
        result["error"] = str(exc)
        log.warning("%s — %s", hostname, exc)
    return result


def save_result(result: dict, output_dir: Path, timestamp: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    safe = result["hostname"].replace("/", "_").replace(" ", "_")
    path = output_dir / f"{safe}_{timestamp}.txt"
    with open(path, "w") as fh:
        fh.write(f"Device:   {result['hostname']}  ({result['host']})\n")
        fh.write(f"Captured: {timestamp}\n")
        fh.write("=" * 72 + "\n")
        if result["error"]:
            fh.write(f"\nERROR: {result['error']}\n")
        else:
            for cmd, output in result["outputs"].items():
                fh.write(f"\n>>> {cmd}\n{output}\n")
    log.info("Saved → %s", path)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run show commands concurrently across a multi-vendor fleet.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--inventory", required=True, metavar="CSV", help="Device inventory CSV")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--command", metavar="CMD", help="Single command to run on every device")
    g.add_argument("--commands", nargs="+", metavar="CMD", help="Multiple commands")
    p.add_argument("--username", default="", help="Override username for all devices")
    p.add_argument("--password", default="", help="Override password for all devices")
    p.add_argument("--secret", default="", help="Override enable secret for all devices")
    p.add_argument("--workers", type=int, default=5, help="Max parallel connections (default: 5)")
    p.add_argument("--output-dir", metavar="DIR", help="Save per-device output files here")
    p.add_argument("--quiet", action="store_true", help="Suppress per-device output to stdout")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    commands = [args.command] if args.command else args.commands
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(args.output_dir) if args.output_dir else None

    try:
        devices = load_inventory(
            args.inventory,
            default_username=args.username,
            default_password=args.password,
            default_secret=args.secret,
        )
    except (FileNotFoundError, KeyError, ValueError) as exc:
        log.error("Inventory error: %s", exc)
        return 1

    log.info(
        "Fleet: %d device(s) | Commands: %d | Workers: %d",
        len(devices), len(commands), args.workers,
    )
    errors = 0

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(run_commands, dev, commands): dev for dev in devices}
        for future in as_completed(futures):
            result = future.result()
            if result["error"]:
                errors += 1
            if output_dir:
                save_result(result, output_dir, timestamp)
            if not args.quiet:
                sep = "=" * 72
                print(f"\n{sep}")
                print(f"Device: {result['hostname']}  ({result['host']})")
                if result["error"]:
                    print(f"ERROR: {result['error']}")
                else:
                    for cmd, output in result["outputs"].items():
                        print(f"\n>>> {cmd}\n{output}")

    log.info(
        "Finished — %d succeeded, %d failed",
        len(devices) - errors, errors,
    )
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
```