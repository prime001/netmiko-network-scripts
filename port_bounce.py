```python
"""
port_bounce.py — Bounce (shut/no-shut) a switchport via Netmiko

Purpose:
    Administratively shuts a port, waits a configurable delay, then
    re-enables it.  Useful for resetting stuck end-devices, cycling PoE,
    or clearing a port security violation without console access.

Usage:
    python port_bounce.py -H 192.168.1.1 -u admin -p secret \
        -i GigabitEthernet0/1 [--delay 5] [--device-type cisco_ios] \
        [--dry-run] [--save]

Prerequisites:
    pip install netmiko
    SSH must be enabled on the target device.
    The supplied account needs privilege level 15 (or equivalent).
"""

import argparse
import getpass
import logging
import sys
import time
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def build_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Bounce a switchport on a Cisco (or compatible) device."
    )
    p.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument(
        "-p", "--password", default=None,
        help="SSH password (omit to be prompted)"
    )
    p.add_argument(
        "-i", "--interface", required=True,
        help="Interface to bounce, e.g. GigabitEthernet0/1 or Gi0/1"
    )
    p.add_argument(
        "--delay", type=float, default=3.0,
        help="Seconds to wait between shut and no-shut (default: 3)"
    )
    p.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)"
    )
    p.add_argument(
        "--port", type=int, default=22,
        help="SSH port (default: 22)"
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Show commands that would run without sending them"
    )
    p.add_argument(
        "--save", action="store_true",
        help="Write memory after bounce (cisco_ios: 'write memory')"
    )
    return p.parse_args()


def get_interface_status(connection, interface: str) -> str:
    output = connection.send_command(f"show interfaces {interface} status")
    if not output:
        output = connection.send_command(f"show interfaces {interface}")
    return output.strip()


def bounce_port(
    connection,
    interface: str,
    delay: float,
    dry_run: bool,
    save: bool,
) -> bool:
    shut_cmds = [f"interface {interface}", "shutdown"]
    noshut_cmds = [f"interface {interface}", "no shutdown"]

    if dry_run:
        log.info("[DRY-RUN] Would send: %s", shut_cmds)
        log.info("[DRY-RUN] Would wait %.1f seconds", delay)
        log.info("[DRY-RUN] Would send: %s", noshut_cmds)
        if save:
            log.info("[DRY-RUN] Would run: write memory")
        return True

    log.info("Shutting down %s …", interface)
    output = connection.send_config_set(shut_cmds)
    log.debug("shut output:\n%s", output)

    log.info("Waiting %.1f seconds …", delay)
    time.sleep(delay)

    log.info("Bringing up %s …", interface)
    output = connection.send_config_set(noshut_cmds)
    log.debug("no-shut output:\n%s", output)

    if save:
        log.info("Saving configuration …")
        save_output = connection.save_config()
        log.debug("save output:\n%s", save_output)

    return True


def main() -> int:
    args = build_args()

    password = args.password or getpass.getpass(f"Password for {args.username}@{args.host}: ")

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": password,
        "port": args.port,
    }

    log.info("Connecting to %s (%s) …", args.host, args.device_type)

    try:
        with ConnectHandler(**device) as conn:
            log.info("Connected.  Checking interface state before bounce …")
            pre_status = get_interface_status(conn, args.interface)
            log.info("Pre-bounce status:\n%s", pre_status)

            success = bounce_port(
                conn,
                args.interface,
                delay=args.delay,
                dry_run=args.dry_run,
                save=args.save,
            )

            if success and not args.dry_run:
                log.info("Checking interface state after bounce …")
                post_status = get_interface_status(conn, args.interface)
                log.info("Post-bounce status:\n%s", post_status)

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 1
    except NetmikoTimeoutException:
        log.error("Connection timed out reaching %s:%d", args.host, args.port)
        return 1
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        return 1

    log.info("Port bounce complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```