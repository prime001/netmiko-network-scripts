```python
"""
firmware_upgrade.py - Stage a Cisco IOS firmware image via SCP and set boot variable.

Purpose:
    Transfer a new IOS image to a Cisco device's flash, verify the MD5 checksum,
    update the boot statement, save config, and optionally schedule a reload.
    Complements firmware_check.py (version auditing) by handling the actual upgrade
    workflow end-to-end.

Usage:
    python firmware_upgrade.py -d 192.168.1.1 -u admin -p secret \
        --image /tmp/c2960-lanbasek9-mz.150-2.SE11.bin \
        --flash-dest flash:/c2960-lanbasek9-mz.150-2.SE11.bin \
        [--md5 <expected_hex>] [--reload] [--reload-in 60]

Prerequisites:
    pip install netmiko
    Device must have SCP enabled:  ip scp server enable
    Credentials must have privilege 15 (or provide --secret for enable).
"""

import argparse
import hashlib
import logging
import sys
from pathlib import Path

from netmiko import ConnectHandler, file_transfer
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def compute_local_md5(path: str) -> str:
    md5 = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            md5.update(chunk)
    return md5.hexdigest()


def flash_free_bytes(conn) -> int:
    output = conn.send_command("show flash: | include bytes free")
    for line in output.splitlines():
        parts = line.split()
        for i, part in enumerate(parts):
            if part == "bytes" and i > 0:
                try:
                    return int(parts[i - 1].replace(",", ""))
                except ValueError:
                    pass
    return -1


def transfer_image(conn, local_path: str, dest: str) -> bool:
    fs, _, filename = dest.partition(":")
    filename = filename.lstrip("/")
    log.info("Transferring %s -> %s:%s via SCP", local_path, fs, filename)
    result = file_transfer(
        conn,
        source_file=local_path,
        dest_file=filename,
        file_system=fs + ":",
        direction="put",
        overwrite_file=False,
    )
    if result.get("file_transferred"):
        log.info("Transfer complete")
    elif result.get("file_exists"):
        log.info("File already present on device, skipping transfer")
    else:
        return False
    return True


def verify_remote_md5(conn, dest: str, expected: str) -> bool:
    log.info("Verifying remote MD5 for %s (may take a minute)", dest)
    output = conn.send_command(f"verify /md5 {dest}", read_timeout=180)
    for line in output.splitlines():
        if "=" in line:
            remote = line.split("=")[-1].strip().lower()
            if remote == expected.lower():
                log.info("MD5 match: %s", remote)
                return True
            log.error("MD5 mismatch — local=%s remote=%s", expected, remote)
            return False
    log.warning("Could not parse MD5 from:\n%s", output)
    return False


def set_boot_variable(conn, dest: str) -> None:
    fs, _, filename = dest.partition(":")
    filename = filename.lstrip("/")
    boot_path = f"{fs}:{filename}"
    log.info("Setting boot system to %s", boot_path)
    conn.send_config_set(["no boot system", f"boot system {boot_path}"])
    conn.send_command("write memory")
    log.info("Config saved")


def schedule_reload(conn, minutes: int) -> None:
    log.info("Scheduling reload in %d minutes", minutes)
    output = conn.send_command(
        f"reload in {minutes}",
        expect_string=r"[Pp]roceed|confirm",
        read_timeout=15,
    )
    if any(w in output.lower() for w in ("proceed", "confirm")):
        conn.send_command("\n", expect_string=r"#", read_timeout=10)
    log.info("Reload scheduled in %d minutes", minutes)


def parse_args():
    p = argparse.ArgumentParser(description="Stage IOS firmware image and set boot variable")
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)
    p.add_argument("--device-type", default="cisco_ios")
    p.add_argument("--secret", default="", help="Enable secret")
    p.add_argument("--image", required=True, help="Local path to firmware .bin")
    p.add_argument("--flash-dest", required=True, help="e.g. flash:/image.bin")
    p.add_argument("--md5", help="Expected MD5 hex (computed locally if omitted)")
    p.add_argument("--reload", action="store_true", help="Schedule reload after staging")
    p.add_argument("--reload-in", type=int, default=60, metavar="MINUTES")
    p.add_argument("--skip-space-check", action="store_true")
    return p.parse_args()


def main():
    args = parse_args()

    image_path = Path(args.image)
    if not image_path.exists():
        log.error("Image not found: %s", args.image)
        sys.exit(1)

    image_mb = image_path.stat().st_size / (1024 * 1024)
    local_md5 = args.md5 or compute_local_md5(args.image)
    log.info("Image: %s  size=%.1f MB  md5=%s", image_path.name, image_mb, local_md5)

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "secret": args.secret,
        "timeout": 30,
    }

    try:
        log.info("Connecting to %s", args.device)
        with ConnectHandler(**device_params) as conn:
            if args.secret:
                conn.enable()

            if not args.skip_space_check:
                free = flash_free_bytes(conn)
                if free > 0:
                    free_mb = free / (1024 * 1024)
                    log.info("Flash free: %.1f MB", free_mb)
                    if free_mb < image_mb * 1.05:
                        log.error("Insufficient flash: %.1f MB free, need %.1f MB", free_mb, image_mb * 1.05)
                        sys.exit(1)

            if not transfer_image(conn, args.image, args.flash_dest):
                log.error("Transfer failed")
                sys.exit(1)

            if not verify_remote_md5(conn, args.flash_dest, local_md5):
                log.error("MD5 mismatch — not updating boot variable")
                sys.exit(1)

            set_boot_variable(conn, args.flash_dest)

            if args.reload:
                schedule_reload(conn, args.reload_in)

        log.info("Upgrade staging complete on %s", args.device)

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", args.device)
        sys.exit(1)
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
```