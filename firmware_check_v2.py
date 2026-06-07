```python
"""
firmware_upgrade_readiness.py - Pre-upgrade readiness checker for Cisco IOS/IOS-XE devices.

Purpose:
    Validates whether a device is ready for a firmware upgrade before a maintenance
    window. Checks available flash space, boot variable configuration, and whether
    the target image is already staged on flash. Exits with code 1 if any check fails,
    making it suitable for use in CI/pre-change automation gates.

Usage:
    python firmware_upgrade_readiness.py -d 192.168.1.1 -u admin -p secret \
        --target-image c2960x-universalk9-mz.152-7.E6.bin --min-flash-mb 128

Prerequisites:
    pip install netmiko
    SSH access to the target device with 'show' privilege (enable optional).
"""

import argparse
import logging
import re
import sys
from dataclasses import dataclass, field
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
class ReadinessResult:
    host: str
    hostname: Optional[str] = None
    current_version: Optional[str] = None
    flash_total_mb: Optional[float] = None
    flash_free_mb: Optional[float] = None
    boot_variable: Optional[str] = None
    target_image_present: bool = False
    checks_passed: list = field(default_factory=list)
    checks_failed: list = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return bool(self.checks_passed) and not self.checks_failed

    def summary(self) -> str:
        status = "READY" if self.ready else "NOT READY"
        lines = [
            f"=== Firmware Upgrade Readiness: {status} ===",
            f"Host         : {self.host}",
            f"Hostname     : {self.hostname or 'unknown'}",
            f"IOS Version  : {self.current_version or 'unknown'}",
        ]
        if self.flash_total_mb is not None:
            lines.append(f"Flash Total  : {self.flash_total_mb:.1f} MB")
        if self.flash_free_mb is not None:
            lines.append(f"Flash Free   : {self.flash_free_mb:.1f} MB")
        lines.append(f"Boot Variable: {self.boot_variable or 'not explicitly set'}")
        lines.append(f"Target Image : {'present' if self.target_image_present else 'absent/not checked'}")
        if self.checks_passed:
            lines.append("\nPassed:")
            for c in self.checks_passed:
                lines.append(f"  [OK]   {c}")
        if self.checks_failed:
            lines.append("\nFailed:")
            for c in self.checks_failed:
                lines.append(f"  [FAIL] {c}")
        return "\n".join(lines)


def _get_version_info(conn) -> tuple:
    output = conn.send_command("show version", use_textfsm=False)
    version = None
    hostname = None
    ver_match = re.search(r"Version\s+(\S+)", output)
    if ver_match:
        version = ver_match.group(1).rstrip(",")
    host_match = re.search(r"^(\S+)\s+uptime", output, re.MULTILINE)
    if host_match:
        hostname = host_match.group(1)
    return version, hostname


def _get_flash_space(conn) -> tuple:
    output = conn.send_command("show flash: | include bytes", use_textfsm=False)
    match = re.search(r"(\d+)\s+bytes total.*?(\d+)\s+bytes free", output)
    if match:
        total_mb = int(match.group(1)) / (1024 * 1024)
        free_mb = int(match.group(2)) / (1024 * 1024)
        return round(total_mb, 1), round(free_mb, 1)
    return None, None


def _get_boot_variable(conn) -> Optional[str]:
    output = conn.send_command("show boot", use_textfsm=False)
    match = re.search(r"BOOT variable\s*=\s*(\S+)", output, re.IGNORECASE)
    if match:
        return match.group(1).rstrip(";")
    return None


def _image_on_flash(conn, image_name: str) -> bool:
    output = conn.send_command(
        f"show flash: | include {image_name}", use_textfsm=False
    )
    return image_name in output


def check_readiness(
    host: str,
    username: str,
    password: str,
    target_image: Optional[str] = None,
    min_flash_mb: float = 64.0,
    device_type: str = "cisco_ios",
    port: int = 22,
    secret: Optional[str] = None,
) -> ReadinessResult:
    result = ReadinessResult(host=host)
    device_params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
    }
    if secret:
        device_params["secret"] = secret

    try:
        log.info("Connecting to %s", host)
        with ConnectHandler(**device_params) as conn:
            if secret:
                conn.enable()
            result.current_version, result.hostname = _get_version_info(conn)
            result.flash_total_mb, result.flash_free_mb = _get_flash_space(conn)
            result.boot_variable = _get_boot_variable(conn)
            if target_image:
                result.target_image_present = _image_on_flash(conn, target_image)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", host)
        result.checks_failed.append("SSH authentication failed")
        return result
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", host)
        result.checks_failed.append("SSH connection timed out")
        return result
    except Exception as exc:
        log.error("Unexpected error on %s: %s", host, exc)
        result.checks_failed.append(f"Connection error: {exc}")
        return result

    if result.flash_free_mb is not None:
        if result.flash_free_mb >= min_flash_mb:
            result.checks_passed.append(
                f"Flash free {result.flash_free_mb:.1f} MB >= required {min_flash_mb} MB"
            )
        else:
            result.checks_failed.append(
                f"Insufficient flash: {result.flash_free_mb:.1f} MB free, need {min_flash_mb} MB"
            )
    else:
        result.checks_failed.append("Could not parse flash space from 'show flash'")

    if result.boot_variable:
        result.checks_passed.append(f"Boot variable explicitly configured: {result.boot_variable}")
    else:
        result.checks_failed.append("Boot variable not set — upgrade may boot wrong image")

    if target_image:
        if result.target_image_present:
            result.checks_passed.append(f"Target image '{target_image}' is staged on flash")
        else:
            result.checks_failed.append(f"Target image '{target_image}' not found on flash")

    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Assess Cisco IOS/IOS-XE firmware upgrade readiness before a maintenance window."
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("--secret", default=None, help="Enable secret (if required)")
    parser.add_argument(
        "--target-image",
        default=None,
        metavar="FILENAME",
        help="Image filename to verify on flash (e.g. c2960x-universalk9-mz.bin)",
    )
    parser.add_argument(
        "--min-flash-mb",
        type=float,
        default=64.0,
        metavar="MB",
        help="Minimum free flash space in MB required to pass (default: 64)",
    )
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    result = check_readiness(
        host=args.device,
        username=args.username,
        password=args.password,
        target_image=args.target_image,
        min_flash_mb=args.min_flash_mb,
        device_type=args.device_type,
        port=args.port,
        secret=args.secret,
    )

    print(result.summary())
    sys.exit(0 if result.ready else 1)
```