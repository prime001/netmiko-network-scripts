running_startup_diff.py - Running vs Startup Configuration Drift Detector

Compares a device's running configuration against its startup configuration
to identify unsaved changes. Reports line-level differences, and optionally
persists or discards uncommitted modifications.

Actions:
    diff (default)  Show unified diff of running vs startup configs
    save            Write running-config to startup-config (write memory)
    revert          Replace running-config with startup-config, discarding
                    any unsaved changes (requires --confirm)

Usage:
    python running_startup_diff.py --host 192.168.1.1 -u admin -p secret

    python running_startup_diff.py --host 10.0.0.1 -u admin -p secret \
        --device-type cisco_nxos --action save

    python running_startup_diff.py --host 10.0.0.1 -u admin -p secret \
        --action revert --confirm

Prerequisites:
    pip install netmiko
    Supported device types: cisco_ios, cisco_xe, cisco_nxos, arista_eos
"""

import argparse
import difflib
import logging
import sys

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

DEVICE_COMMANDS = {
    "cisco_ios": {
        "running": "show running-config",
        "startup": "show startup-config",
        "save": "write memory",
        "revert": "configure replace nvram:startup-config force",
    },
    "cisco_xe": {
        "running": "show running-config",
        "startup": "show startup-config",
        "save": "write memory",
        "revert": "configure replace nvram:startup-config force",
    },
    "cisco_nxos": {
        "running": "show running-config",
        "startup": "show startup-config",
        "save": "copy running-config startup-config",
        "revert": "rollback running-config startup-config verbose",
    },
    "arista_eos": {
        "running": "show running-config",
        "startup": "show startup-config",
        "save": "write memory",
        "revert": "configure replace startup-config",
    },
}


def strip_volatile_lines(config: str) -> list:
    """Remove timestamp and version header lines that always differ."""
    skip_fragments = (
        "Last configuration change",
        "NVRAM config last",
        "! Time:",
        "! Last",
    )
    return [
        line for line in config.splitlines()
        if not any(frag in line for frag in skip_fragments)
    ]


def compute_diff(running: str, startup: str, host: str) -> list:
    running_lines = strip_volatile_lines(running)
    startup_lines = strip_volatile_lines(startup)
    return list(
        difflib.unified_diff(
            startup_lines,
            running_lines,
            fromfile=f"{host}:startup-config",
            tofile=f"{host}:running-config",
            lineterm="",
        )
    )


def action_diff(conn, cmds: dict, host: str) -> int:
    log.info("Retrieving running-config from %s", host)
    running = conn.send_command(cmds["running"])
    log.info("Retrieving startup-config from %s", host)
    startup = conn.send_command(cmds["startup"])

    diff = compute_diff(running, startup, host)
    if not diff:
        print(f"[IN SYNC] {host}: running and startup configs are identical — no unsaved changes")
        return 0

    changed = [l for l in diff if l.startswith(("+", "-")) and not l.startswith(("---", "+++"))]
    print(f"[DRIFT DETECTED] {host}: {len(changed)} line(s) differ\n")

    for line in diff:
        if line.startswith("+") and not line.startswith("+++"):
            print(f"\033[32m{line}\033[0m")
        elif line.startswith("-") and not line.startswith("---"):
            print(f"\033[31m{line}\033[0m")
        else:
            print(line)
    return 1


def action_save(conn, cmds: dict, host: str) -> int:
    log.info("Writing running-config to startup-config on %s", host)
    output = conn.send_command_timing(cmds["save"])
    log.debug("Save output: %s", output.strip())
    print(f"[SAVED] {host}: running-config written to startup-config")
    return 0


def action_revert(conn, cmds: dict, host: str) -> int:
    log.info("Reverting running-config to startup-config on %s", host)
    output = conn.send_command_timing(cmds["revert"], delay_factor=4)
    log.debug("Revert output: %s", output.strip())
    print(f"[REVERTED] {host}: running-config replaced with startup-config")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Detect, persist, or discard running-config drift vs startup-config"
    )
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("--username", "-u", required=True)
    p.add_argument("--password", "-p", required=True)
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(DEVICE_COMMANDS.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument(
        "--action",
        choices=["diff", "save", "revert"],
        default="diff",
        help="Operation to perform (default: diff)",
    )
    p.add_argument(
        "--confirm",
        action="store_true",
        help="Required safety flag for --action revert",
    )
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--timeout", type=int, default=30, help="SSH connection timeout in seconds")
    p.add_argument("--verbose", "-v", action="store_true")
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.action == "revert" and not args.confirm:
        print(
            "ERROR: --action revert requires --confirm to prevent accidental config loss",
            file=sys.stderr,
        )
        return 2

    cmds = DEVICE_COMMANDS[args.device_type]
    device = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "timeout": args.timeout,
    }

    try:
        log.info("Connecting to %s (%s)", args.host, args.device_type)
        with ConnectHandler(**device) as conn:
            if args.action == "diff":
                return action_diff(conn, cmds, args.host)
            elif args.action == "save":
                return action_save(conn, cmds, args.host)
            else:
                return action_revert(conn, cmds, args.host)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 3
    except NetmikoTimeoutException:
        log.error("Connection timed out: %s", args.host)
        return 4
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        return 5


if __name__ == "__main__":
    sys.exit(main())