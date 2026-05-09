Here's the script — you can save it as `boot_integrity_check.py` in your repo:

```python
"""
boot_integrity_check.py — Boot variable and flash integrity auditor

Verifies pre-upgrade readiness: boot variables, flash image presence, MD5
hash validation, and available memory thresholds. Complements firmware_check.py
(which compares running vs target versions) by auditing the boot environment
*before* a planned upgrade.

Usage:
    python boot_integrity_check.py -d 192.168.1.1 -u admin -p secret
    python boot_integrity_check.py -d 192.168.1.1 -u admin -p secret \
        --image c2960x-universalk9-mz.152-7.E5.bin \
        --min-flash-mb 256 --min-ram-mb 512 --verify-md5

Prerequisites:
    pip install netmiko
    Target device: Cisco IOS/IOS-XE (show boot, dir flash:, show version)
"""

import argparse
import logging
import re
import sys

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Audit boot variables and flash integrity before firmware upgrades"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument("--secret", default="", help="Enable secret (if required)")
    parser.add_argument("--device-type", default="cisco_ios")
    parser.add_argument(
        "--image", help="Expected flash image filename to verify presence"
    )
    parser.add_argument(
        "--min-flash-mb", type=int, default=64,
        help="Minimum free flash space in MB (default: 64)"
    )
    parser.add_argument(
        "--min-ram-mb", type=int, default=256,
        help="Minimum free RAM in MB (default: 256)"
    )
    parser.add_argument(
        "--verify-md5", action="store_true",
        help="Run verify /md5 on the target image (slow on large images)"
    )
    parser.add_argument(
        "--expected-md5", help="Expected MD5 hash to compare against"
    )
    return parser.parse_args()


def get_boot_vars(conn):
    output = conn.send_command("show boot")
    boot_path = re.search(r"BOOT variable\s*=\s*(\S+)", output, re.IGNORECASE)
    return boot_path.group(1) if boot_path else None


def parse_flash_contents(conn):
    output = conn.send_command("dir flash:")
    files = []
    for line in output.splitlines():
        m = re.match(r"\s*\d+\s+[-drwx]+\s+(\d+)\s+\S+\s+\S+\s+(.+)", line)
        if m:
            files.append({"size_bytes": int(m.group(1)), "name": m.group(2).strip()})

    free_match = re.search(r"(\d+)\s+bytes free", output)
    free_bytes = int(free_match.group(1)) if free_match else 0
    return files, free_bytes


def parse_memory(conn):
    output = conn.send_command("show version")
    m = re.search(r"with\s+(\d+)K[/\w]*/(\d+)K bytes of memory", output, re.IGNORECASE)
    if m:
        return int(m.group(1)) // 1024, int(m.group(2)) // 1024
    m = re.search(r"(\d+)K bytes of physical memory", output, re.IGNORECASE)
    if m:
        total_mb = int(m.group(1)) // 1024
        return total_mb, total_mb
    return None, None


def verify_image_md5(conn, image_path, expected_md5=None):
    log.info("Running MD5 verification on %s (may take 1-2 minutes)...", image_path)
    output = conn.send_command(
        f"verify /md5 {image_path}", read_timeout=180
    )
    m = re.search(r"MD5 of\s+\S+\s+=\s+([0-9a-fA-F]{32})", output)
    computed = m.group(1).lower() if m else None
    if expected_md5 and computed:
        return computed, computed == expected_md5.lower()
    return computed, None


def run_audit(args):
    device = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "secret": args.secret,
    }

    results = {"device": args.device, "checks": [], "passed": True}

    def record(label, ok, detail=""):
        status = "PASS" if ok else "FAIL"
        results["checks"].append({"check": label, "status": status, "detail": detail})
        if not ok:
            results["passed"] = False
        log.info("[%s] %s%s", status, label, f" — {detail}" if detail else "")

    try:
        log.info("Connecting to %s...", args.device)
        with ConnectHandler(**device) as conn:
            if args.secret:
                conn.enable()

            boot_var = get_boot_vars(conn)
            record(
                "Boot variable set",
                bool(boot_var),
                boot_var or "No BOOT variable found"
            )

            flash_files, free_bytes = parse_flash_contents(conn)
            free_mb = free_bytes // (1024 * 1024)
            record(
                "Flash free space",
                free_mb >= args.min_flash_mb,
                f"{free_mb} MB free (threshold: {args.min_flash_mb} MB)"
            )

            if args.image:
                names = [f["name"] for f in flash_files]
                image_present = any(args.image in n for n in names)
                record("Target image present", image_present, args.image)

                if image_present and args.verify_md5:
                    image_path = f"flash:{args.image}"
                    computed, match = verify_image_md5(
                        conn, image_path, args.expected_md5
                    )
                    if args.expected_md5:
                        record(
                            "MD5 hash match",
                            match is True,
                            f"computed={computed}, expected={args.expected_md5.lower()}"
                        )
                    else:
                        record("MD5 computed", bool(computed), computed or "failed")

            total_mb, free_ram_mb = parse_memory(conn)
            if total_mb is not None:
                record(
                    "RAM meets threshold",
                    total_mb >= args.min_ram_mb,
                    f"{total_mb} MB total (threshold: {args.min_ram_mb} MB)"
                )

    except AuthenticationException:
        log.error("Authentication failed for %s", args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.device)
        sys.exit(1)

    return results


def print_summary(results):
    print("\n" + "=" * 60)
    print(f"Boot Integrity Report — {results['device']}")
    print("=" * 60)
    for check in results["checks"]:
        marker = "+" if check["status"] == "PASS" else "!"
        print(f"  [{marker}] {check['check']}: {check['detail']}")
    overall = "READY" if results["passed"] else "NOT READY"
    print(f"\nOverall: {overall}")
    print("=" * 60)


if __name__ == "__main__":
    args = parse_args()
    results = run_audit(args)
    print_summary(results)
    sys.exit(0 if results["passed"] else 1)
```

This is `boot_integrity_check.py` — it audits the *boot environment* rather than comparing version strings, which is what the existing firmware_check scripts do. Key distinctions:

- Checks `BOOT variable` is actually set (a common pre-upgrade miss)
- Verifies the target image filename exists in flash before upgrade
- Optionally runs `verify /md5` with optional hash comparison for image integrity
- Parses free flash space and total RAM against configurable thresholds
- Exits 0/1 so it can gate CI/change-window scripts
- `--verify-md5` flag is opt-in since it can take 1-2 minutes on large images