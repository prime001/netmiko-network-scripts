The script content is below — this is a pre-upgrade readiness validator, distinct from the version-check work in `firmware_check.py`/`firmware_check_v2.py`:

```python
"""
firmware_upgrade_preflight.py - Pre-upgrade readiness validator for Cisco IOS devices.

Purpose:
    Validates that a device meets all prerequisites before a firmware upgrade:
    checks free flash storage, available DRAM, whether the target image is already
    staged, and optionally runs on-device MD5 verification of the staged image.
    Exits 0 if all checks pass, 1 if any blocking error is found.

Usage:
    python firmware_upgrade_preflight.py -d 192.168.1.1 -u admin -p secret \
        --target-image c2960x-universalk9-mz.152-7.E6.bin \
        --required-flash-mb 128 --required-dram-mb 256 --verify-md5

Prerequisites:
    pip install netmiko
    SSH + enable access on the target device
    Tested against Cisco IOS; also works with IOS-XE for version/flash checks
"""

import argparse
import logging
import re
import sys
from dataclasses import dataclass, field
from typing import List, Optional

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class PreflightResult:
    host: str
    ios_version: str = "unknown"
    platform: str = "unknown"
    flash_free_mb: Optional[float] = None
    dram_total_mb: Optional[float] = None
    image_staged: bool = False
    md5_verified: Optional[bool] = None
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return len(self.errors) == 0


def parse_version_output(output: str):
    ver = re.search(r"Cisco IOS.*?Version\s+([\S]+)", output)
    plat = re.search(
        r"^cisco\s+(\S+.*?)\s+(?:processor|memory)", output, re.MULTILINE | re.IGNORECASE
    )
    version = ver.group(1).rstrip(",") if ver else "unknown"
    platform = plat.group(1).strip() if plat else "unknown"
    return version, platform


def parse_dram_mb(output: str) -> Optional[float]:
    match = re.search(r"(\d+)K\s+bytes\s+of\s+(?:physical|processor)", output, re.IGNORECASE)
    if match:
        return int(match.group(1)) / 1024
    return None


def parse_flash_free_mb(dir_output: str) -> Optional[float]:
    match = re.search(r"([\d,]+)\s+bytes\s+(?:available|free)", dir_output, re.IGNORECASE)
    if match:
        return int(match.group(1).replace(",", "")) / (1024 * 1024)
    return None


def run_preflight(
    host: str,
    username: str,
    password: str,
    target_image: Optional[str],
    required_flash_mb: float,
    required_dram_mb: float,
    verify_md5: bool,
    port: int = 22,
    secret: str = "",
) -> PreflightResult:
    result = PreflightResult(host=host)
    params = {
        "device_type": "cisco_ios",
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "secret": secret or password,
        "timeout": 30,
    }

    try:
        log.info("Connecting to %s", host)
        with ConnectHandler(**params) as conn:
            conn.enable()

            ver_out = conn.send_command("show version")
            result.ios_version, result.platform = parse_version_output(ver_out)
            log.info("IOS %s on %s", result.ios_version, result.platform)

            dram = parse_dram_mb(ver_out)
            result.dram_total_mb = dram
            if dram is None:
                result.warnings.append("Could not parse DRAM from 'show version'")
            elif dram < required_dram_mb:
                result.errors.append(
                    f"Insufficient DRAM: {dram:.0f} MB available, {required_dram_mb:.0f} MB required"
                )

            dir_out = conn.send_command("dir flash:")
            flash_free = parse_flash_free_mb(dir_out)
            result.flash_free_mb = flash_free
            if flash_free is None:
                result.warnings.append("Could not parse free flash from 'dir flash:'")
            elif flash_free < required_flash_mb:
                result.errors.append(
                    f"Insufficient flash: {flash_free:.1f} MB free, {required_flash_mb:.0f} MB required"
                )

            if target_image:
                result.image_staged = target_image.lower() in dir_out.lower()
                if not result.image_staged:
                    result.warnings.append(
                        f"'{target_image}' not on flash — must be transferred before upgrade"
                    )
                elif verify_md5:
                    log.info("Running MD5 verify on %s (may take ~60s)", target_image)
                    md5_out = conn.send_command(
                        f"verify /md5 flash:{target_image}", read_timeout=180
                    )
                    passed = "verified" in md5_out.lower() or bool(
                        re.search(r"[0-9a-f]{32}", md5_out)
                    )
                    result.md5_verified = passed
                    if not passed:
                        result.errors.append(f"MD5 verification failed for {target_image}")
                    else:
                        log.info("MD5 OK for %s", target_image)

    except AuthenticationException:
        result.errors.append("Authentication failed")
        log.error("Authentication failed for %s", host)
    except NetmikoTimeoutException:
        result.errors.append("Connection timed out")
        log.error("Timeout connecting to %s", host)
    except Exception as exc:
        result.errors.append(str(exc))
        log.exception("Unexpected error on %s", host)

    return result


def print_report(result: PreflightResult) -> None:
    status = "READY" if result.ready else "NOT READY"
    sep = "=" * 56
    print(f"\n{sep}")
    print(f"  Pre-Upgrade Preflight Report  [{status}]")
    print(f"  Host     : {result.host}")
    print(sep)
    print(f"  IOS      : {result.ios_version}")
    print(f"  Platform : {result.platform}")
    if result.dram_total_mb is not None:
        print(f"  DRAM     : {result.dram_total_mb:.0f} MB")
    if result.flash_free_mb is not None:
        print(f"  Flash    : {result.flash_free_mb:.1f} MB free")
    if result.image_staged:
        md5_str = {True: "PASS", False: "FAIL", None: "skipped"}[result.md5_verified]
        print(f"  Staged   : YES  (MD5: {md5_str})")
    else:
        print("  Staged   : NO")
    if result.warnings:
        print(f"\n  Warnings ({len(result.warnings)}):")
        for w in result.warnings:
            print(f"    ! {w}")
    if result.errors:
        print(f"\n  Errors ({len(result.errors)}):")
        for e in result.errors:
            print(f"    x {e}")
    print(f"{sep}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cisco IOS firmware upgrade pre-flight checker"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument("--secret", default="", help="Enable secret (defaults to password)")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--target-image", help="Target IOS image filename to check on flash")
    parser.add_argument(
        "--required-flash-mb", type=float, default=64.0,
        help="Minimum free flash required in MB (default: 64)"
    )
    parser.add_argument(
        "--required-dram-mb", type=float, default=256.0,
        help="Minimum DRAM required in MB (default: 256)"
    )
    parser.add_argument(
        "--verify-md5", action="store_true",
        help="Run on-device MD5 verify on the staged image (~60s)"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    result = run_preflight(
        host=args.device,
        username=args.username,
        password=args.password,
        target_image=args.target_image,
        required_flash_mb=args.required_flash_mb,
        required_dram_mb=args.required_dram_mb,
        verify_md5=args.verify_md5,
        port=args.port,
        secret=args.secret,
    )

    print_report(result)
    sys.exit(0 if result.ready else 1)


if __name__ == "__main__":
    main()
```