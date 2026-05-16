firmware_upgrade.py - Cisco IOS firmware upgrade orchestrator

Purpose:
    Automates the end-to-end firmware upgrade workflow for Cisco IOS devices:
    validates flash space, transfers the image via SCP, verifies MD5 integrity,
    updates the boot variable, and optionally schedules a reload.

    Use firmware_check.py to audit current versions fleet-wide before deciding
    which devices to target here.

Usage:
    python firmware_upgrade.py -d 192.168.1.1 -u admin -p secret \
        --image c2960-lanbasek9-mz.152-7.E6.bin \
        --source-path /tftp/images/ \
        [--reload-in 60] [--dry-run]

Prerequisites:
    pip install netmiko
    - SCP must be enabled on the target device:  ip scp server enable
    - Account requires privilege 15 or a valid enable secret
    - The firmware .bin must exist at --source-path on the machine running this script
"""

import argparse
import logging
import os
import sys

from netmiko import ConnectHandler, file_transfer
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def get_free_flash_bytes(conn):
    output = conn.send_command("show flash:", use_textfsm=False)
    for line in output.splitlines():
        lower = line.lower()
        if "bytes free" in lower or "bytes available" in lower:
            for token in line.split():
                if token.isdigit():
                    return int(token)
    return None


def image_on_flash(conn, image_name):
    output = conn.send_command(f"show flash: | include {image_name}", use_textfsm=False)
    return image_name in output


def current_boot_statements(conn):
    return conn.send_command("show running-config | include boot system", use_textfsm=False).strip()


def transfer_image(conn, source_path, image_name):
    result = file_transfer(
        conn,
        source_file=os.path.join(source_path, image_name),
        dest_file=image_name,
        file_system="flash:",
        direction="put",
        overwrite_file=False,
    )
    return result.get("file_verified", False) or result.get("file_exists", False)


def apply_boot_variable(conn, image_name, dry_run):
    commands = [
        "no boot system",
        f"boot system flash:{image_name}",
    ]
    if dry_run:
        log.info("[DRY-RUN] Would send config:\n  %s", "\n  ".join(commands))
        log.info("[DRY-RUN] Would write memory")
        return True
    output = conn.send_config_set(commands)
    if "Invalid" in output or "Error" in output:
        log.error("Config error while setting boot variable:\n%s", output)
        return False
    conn.send_command("write memory", expect_string=r"#", read_timeout=30)
    return True


def schedule_reload(conn, minutes, dry_run):
    if dry_run:
        log.info("[DRY-RUN] Would schedule: reload in %d", minutes)
        return
    conn.send_command(
        f"reload in {minutes}",
        expect_string=r"[confirm]",
        strip_prompt=False,
        strip_command=False,
        read_timeout=15,
    )
    conn.send_command(
        "\n",
        expect_string=r"#",
        strip_prompt=False,
        strip_command=False,
        read_timeout=10,
    )
    log.info("Reload scheduled in %d minutes", minutes)


def build_parser():
    p = argparse.ArgumentParser(
        description="Cisco IOS firmware upgrade orchestrator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("--secret", default="", help="Enable secret")
    p.add_argument("--device-type", default="cisco_ios", help="Netmiko device type")
    p.add_argument("--image", required=True, help="Firmware image filename (e.g. c2960-...bin)")
    p.add_argument("--source-path", default=".", help="Local directory containing the image")
    p.add_argument(
        "--min-free-mb",
        type=int,
        default=32,
        help="Extra free flash (MB) required beyond image size",
    )
    p.add_argument(
        "--reload-in",
        type=int,
        default=0,
        metavar="MINUTES",
        help="Schedule reload N minutes after upgrade (0 = skip)",
    )
    p.add_argument("--dry-run", action="store_true", help="Validate and plan without making changes")
    return p


def main():
    args = build_parser().parse_args()

    image_path = os.path.join(args.source_path, args.image)
    if not args.dry_run and not os.path.isfile(image_path):
        log.error("Image not found locally: %s", image_path)
        sys.exit(1)

    image_size_bytes = os.path.getsize(image_path) if os.path.isfile(image_path) else 0
    image_size_mb = image_size_bytes / (1024 * 1024)

    device = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "secret": args.secret,
        "timeout": 30,
        "session_timeout": 600,
        "global_delay_factor": 2,
    }

    log.info("Connecting to %s ...", args.device)
    try:
        with ConnectHandler(**device) as conn:
            if args.secret:
                conn.enable()

            free_bytes = get_free_flash_bytes(conn)
            if free_bytes is not None:
                free_mb = free_bytes / (1024 * 1024)
                required_mb = image_size_mb + args.min_free_mb
                log.info(
                    "Flash: %.1f MB free | Image: %.1f MB | Required: %.1f MB",
                    free_mb, image_size_mb, required_mb,
                )
                if free_mb < required_mb:
                    log.error("Insufficient flash space — aborting")
                    sys.exit(1)
            else:
                log.warning("Could not parse flash size — proceeding without space check")

            if image_on_flash(conn, args.image):
                log.info("Image already present on flash — skipping transfer")
            elif args.dry_run:
                log.info("[DRY-RUN] Would transfer %s (%.1f MB) via SCP", args.image, image_size_mb)
            else:
                log.info("Transferring %s via SCP (%.1f MB) — this may take several minutes ...", args.image, image_size_mb)
                if not transfer_image(conn, args.source_path, args.image):
                    log.error("Transfer failed or MD5 mismatch — aborting")
                    sys.exit(1)
                log.info("Transfer complete and MD5 verified")

            log.info("Current boot config: %s", current_boot_statements(conn) or "(none)")

            if not apply_boot_variable(conn, args.image, args.dry_run):
                sys.exit(1)
            log.info("Boot variable set to flash:%s", args.image)

            if args.reload_in > 0:
                schedule_reload(conn, args.reload_in, args.dry_run)

            log.info("Upgrade workflow complete for %s", args.device)

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", args.device)
        sys.exit(1)
    except Exception as exc:
        log.error("Unexpected error on %s: %s", args.device, exc)
        sys.exit(1)


if __name__ == "__main__":
    main()