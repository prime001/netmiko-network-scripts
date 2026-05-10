The write was blocked — outputting the script content directly as requested:

```
"""
firmware_upgrade_readiness.py - Pre-upgrade readiness validator for Cisco IOS/IOS-XE devices.

Purpose:
    Answers the go/no-go question before a firmware upgrade maintenance window.
    Checks available flash space, whether the target image is already staged,
    supervisor redundancy state, and concurrent user sessions. Exits 0 on GO,
    1 on NO-GO so it can gate automation pipelines.

Usage:
    python firmware_upgrade_readiness.py -d 192.168.1.1 -u admin -p secret \
        --target-image c3750e-universalk9-mz.152-4.E10.bin --required-space 64

    # Pipe-friendly: exit code reflects verdict
    python firmware_upgrade_readiness.py -d 10.0.0.1 -u admin -p s3cr3t && echo "Safe to upgrade"

Prerequisites:
    pip install netmiko
    SSH enabled on the device; account needs privilege 15 or enable secret via --secret.
"""

import argparse
import logging
import re
import sys
from dataclasses import dataclass, field
from typing import Optional

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class ReadinessReport:
    host: str
    current_version: str = "unknown"
    free_flash_mb: Optional[float] = None
    required_flash_mb: float = 64.0
    target_image_staged: bool = False
    redundancy_state: str = "unknown"
    active_sessions: int = 0
    checks_passed: list = field(default_factory=list)
    checks_failed: list = field(default_factory=list)

    @property
    def verdict(self) -> str:
        return "GO" if not self.checks_failed else "NO-GO"

    def print_summary(self):
        width = 62
        print("\n" + "=" * width)
        print(f"  UPGRADE READINESS — {self.host}")
        print("=" * width)
        print(f"  Current version  : {self.current_version}")
        if self.free_flash_mb is not None:
            print(f"  Free flash       : {self.free_flash_mb:.1f} MB")
        else:
            print("  Free flash       : unknown")
        print(f"  Target staged    : {'Yes' if self.target_image_staged else 'No'}")
        print(f"  Redundancy       : {self.redundancy_state}")
        print(f"  Active sessions  : {self.active_sessions}")
        print()
        for item in self.checks_passed:
            print(f"  [PASS] {item}")
        for item in self.checks_failed:
            print(f"  [FAIL] {item}")
        print()
        print(f"  VERDICT: {self.verdict}")
        print("=" * width + "\n")


def _parse_free_flash_mb(output: str) -> Optional[float]:
    match = re.search(r"(\d+)\s+bytes\s+available", output)
    if match:
        return int(match.group(1)) / (1024 * 1024)
    return None


def _image_present(output: str, image_name: str) -> bool:
    return image_name.lower() in output.lower()


def _count_active_sessions(output: str) -> int:
    count = 0
    for line in output.splitlines():
        if re.search(r"\bssh\b", line, re.IGNORECASE) and re.search(
            r"\bEstablished\b|\bActive\b", line, re.IGNORECASE
        ):
            count += 1
    return count


def run_readiness_check(args) -> ReadinessReport:
    report = ReadinessReport(host=args.device, required_flash_mb=args.required_space)

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "secret": args.secret or args.password,
        "timeout": args.timeout,
    }

    log.info("Connecting to %s ...", args.device)
    try:
        with ConnectHandler(**device_params) as conn:
            conn.enable()

            ver_out = conn.send_command("show version", use_textfsm=False)
            m = re.search(r"Cisco IOS.*?Version\s+([\S]+)", ver_out, re.IGNORECASE)
            if m:
                report.current_version = m.group(1).rstrip(",")
                report.checks_passed.append(f"Version detected: {report.current_version}")
            else:
                report.checks_failed.append("Could not parse IOS version from 'show version'")

            flash_out = conn.send_command("dir flash:", use_textfsm=False)
            report.free_flash_mb = _parse_free_flash_mb(flash_out)

            if report.free_flash_mb is not None:
                if report.free_flash_mb >= report.required_flash_mb:
                    report.checks_passed.append(
                        f"Flash space OK: {report.free_flash_mb:.1f} MB free "
                        f"(need {report.required_flash_mb:.0f} MB)"
                    )
                else:
                    report.checks_failed.append(
                        f"Insufficient flash: {report.free_flash_mb:.1f} MB free, "
                        f"need {report.required_flash_mb:.0f} MB"
                    )
            else:
                report.checks_failed.append("Could not determine free flash space")

            if args.target_image:
                report.target_image_staged = _image_present(flash_out, args.target_image)
                if report.target_image_staged:
                    report.checks_passed.append(f"Target image staged: {args.target_image}")
                else:
                    report.checks_failed.append(f"Target image NOT on flash: {args.target_image}")

            redun_out = conn.send_command("show redundancy", use_textfsm=False)
            if "Active" in redun_out and "Standby" in redun_out:
                report.redundancy_state = "Active/Standby"
                report.checks_passed.append("Redundancy: Active/Standby (SSO upgrade path available)")
            elif re.search(r"simplex|no redundancy", redun_out, re.IGNORECASE):
                report.redundancy_state = "Simplex"
                report.checks_failed.append("No RP redundancy — upgrade will cause full reload outage")
            else:
                report.redundancy_state = "Single-supervisor"
                report.checks_passed.append("Single-supervisor device — reload expected, no SSO")

            users_out = conn.send_command("show users", use_textfsm=False)
            report.active_sessions = _count_active_sessions(users_out)
            if report.active_sessions <= 1:
                report.checks_passed.append(
                    f"Active SSH sessions: {report.active_sessions} (safe to proceed)"
                )
            else:
                report.checks_failed.append(
                    f"{report.active_sessions} concurrent SSH sessions — "
                    "notify users before reload"
                )

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.device)
        sys.exit(1)
    except Exception as exc:
        log.error("Unexpected error on %s: %s", args.device, exc)
        sys.exit(1)

    return report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Validate Cisco IOS/IOS-XE device readiness before a firmware upgrade.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-d", "--device", required=True, help="Device hostname or IP")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("-s", "--secret", default=None, help="Enable secret (defaults to password)")
    p.add_argument("--device-type", default="cisco_ios", help="Netmiko device type")
    p.add_argument(
        "--target-image",
        default=None,
        metavar="FILENAME",
        help="Image filename to verify on flash",
    )
    p.add_argument(
        "--required-space",
        type=float,
        default=64.0,
        metavar="MB",
        help="Minimum free flash in MB",
    )
    p.add_argument("--timeout", type=int, default=30, help="SSH timeout in seconds")
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()
    report = run_readiness_check(args)
    report.print_summary()
    sys.exit(0 if report.verdict == "GO" else 1)
```