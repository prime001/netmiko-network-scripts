This is a different repo — the portfolio scripts mentioned aren't here. I'll write the script directly.

```python
"""
012_safe_config_push.py — Safe Configuration Push with Rollback Window

Purpose:
    Pushes configuration changes to a network device with an automatic rollback
    safety net using the device's built-in reload timer. If the change breaks
    connectivity or fails validation, the device reloads to its last saved
    (startup) config without any manual intervention.

    This implements the standard "reload in X / reload cancel" pattern used in
    production change windows: set a timer before touching config, verify the
    change works, then confirm to cancel. Silence or connectivity loss = rollback.

Usage:
    python 012_safe_config_push.py --host 192.168.1.1 --username admin \\
        --password secret --config-file acl_changes.cfg --window 5

    python 012_safe_config_push.py -H 10.0.0.1 -u admin -p secret \\
        -c bgp_update.cfg --window 10 --verify-command "show ip bgp summary"

Prerequisites:
    - pip install netmiko
    - Tested on Cisco IOS / IOS-XE; NX-OS requires --device-type cisco_nxos
    - Config file: one IOS command per line, blank lines and ! comments ignored
    - Startup-config must reflect the pre-change baseline (write mem beforehand)
    - The rollback timer window must exceed your validation time
"""

import argparse
import logging
import sys

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger(__name__)


def load_config_commands(path):
    with open(path) as fh:
        lines = [ln.rstrip() for ln in fh if ln.strip() and not ln.lstrip().startswith("!")]
    if not lines:
        raise ValueError(f"No commands found in {path}")
    return lines


def set_reload_timer(conn, minutes):
    log.info("Arming rollback timer: reload in %d min", minutes)
    output = conn.send_command_timing(f"reload in {minutes}")
    if any(kw in output.lower() for kw in ("proceed", "confirm", "save")):
        output += conn.send_command_timing("y")
    log.debug("Timer output: %s", output.strip())


def cancel_reload_timer(conn):
    log.info("Cancelling rollback timer")
    output = conn.send_command_timing("reload cancel")
    if "cancelled" not in output.lower() and "no reload" not in output.lower():
        log.warning("Unexpected cancel output: %s", output.strip())
    return output


def push_config(conn, commands):
    log.info("Pushing %d command(s)", len(commands))
    output = conn.send_config_set(commands)
    log.debug("Config output:\n%s", output)
    return output


def verify(conn, command):
    log.info("Verification: %s", command)
    output = conn.send_command(command)
    print("\n--- Verification Output ---")
    print(output)
    print("---------------------------\n")
    return output


def save_running_config(conn):
    log.info("Writing memory")
    conn.save_config()


def build_device_params(args):
    return {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "secret": args.enable_secret if args.enable_secret else args.password,
        "timeout": args.timeout,
        "session_log": args.session_log or None,
    }


def parse_args():
    p = argparse.ArgumentParser(
        description="Push IOS config with automatic reload-based rollback safety net",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--host", "-H", required=True, help="Device IP or hostname")
    p.add_argument("--username", "-u", required=True, help="SSH username")
    p.add_argument("--password", "-p", required=True, help="SSH password")
    p.add_argument("--enable-secret", "-e", default="", help="Enable secret (falls back to password)")
    p.add_argument("--config-file", "-c", required=True, help="File of IOS commands to push")
    p.add_argument("--window", "-w", type=int, default=5,
                   help="Rollback window in minutes — device reloads if you don't confirm")
    p.add_argument("--device-type", "-t", default="cisco_ios",
                   help="Netmiko device type")
    p.add_argument("--verify-command", "-v", default="show running-config | section last",
                   help="Show command to run after push for manual eyeball")
    p.add_argument("--no-save", action="store_true",
                   help="Skip 'write mem' after confirming the change")
    p.add_argument("--timeout", type=int, default=30, help="SSH connect timeout (seconds)")
    p.add_argument("--session-log", help="Write full session transcript to this file")
    return p.parse_args()


def main():
    args = parse_args()

    try:
        commands = load_config_commands(args.config_file)
    except FileNotFoundError:
        log.error("Config file not found: %s", args.config_file)
        sys.exit(1)
    except ValueError as exc:
        log.error("%s", exc)
        sys.exit(1)

    log.info("Connecting to %s as %s", args.host, args.username)
    try:
        with ConnectHandler(**build_device_params(args)) as conn:
            conn.enable()
            log.info("In enable mode on %s", args.host)

            set_reload_timer(conn, args.window)

            try:
                push_config(conn, commands)
            except Exception as exc:
                log.error("Config push error: %s — cancelling timer", exc)
                cancel_reload_timer(conn)
                sys.exit(1)

            verify(conn, args.verify_command)

            print(f"Rollback timer is running. Device reloads in ~{args.window} min if not confirmed.")
            try:
                answer = input("Confirm change is healthy — cancel rollback and save? [y/N]: ")
            except EOFError:
                answer = ""

            if answer.strip().lower() == "y":
                cancel_reload_timer(conn)
                if not args.no_save:
                    save_running_config(conn)
                log.info("Change committed on %s", args.host)
            else:
                log.warning("Change not confirmed — rollback timer active on %s", args.host)
                log.warning("Device will reload in under %d min and restore startup-config", args.window)
                sys.exit(2)

    except NetmikoAuthenticationException:
        log.error("Authentication failed: %s@%s", args.username, args.host)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out: %s", args.host)
        sys.exit(1)
    except KeyboardInterrupt:
        log.warning("Interrupted — rollback timer may still be active on %s!", args.host)
        sys.exit(130)


if __name__ == "__main__":
    main()
```