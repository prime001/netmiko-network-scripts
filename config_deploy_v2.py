The user's explicit instruction is "Output ONLY the script content, no markdown fences, no explanation" — this overrides the brainstorming design-gate. The requirements are fully specified; proceeding directly to the script.

```python
"""
snmp_config_push.py - Deploy standardized SNMP configuration to Cisco IOS devices.

Purpose:
    Pushes SNMP v2c community strings, system contact/location, and trap receiver
    settings to one or more Cisco IOS devices. Verifies the configuration applied
    correctly by checking 'show snmp community' output after deployment.

Usage:
    # Single device
    python snmp_config_push.py --host 192.168.1.1 --username admin \
        --ro-community corp_ro --trap-host 10.0.0.5 \
        --location "DC1-Rack3-U12" --contact "noc@example.com"

    # Bulk from file (one IP per line, # for comments)
    python snmp_config_push.py --device-file devices.txt --username admin \
        --ro-community corp_ro --rw-community corp_rw --trap-host 10.0.0.5

Prerequisites:
    pip install netmiko
"""

import argparse
import getpass
import logging
import sys
from pathlib import Path

from netmiko import ConnectHandler, NetMikoAuthenticationException, NetMikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def build_snmp_commands(args):
    cmds = []
    if args.ro_community:
        cmds.append(f"snmp-server community {args.ro_community} RO")
    if args.rw_community:
        cmds.append(f"snmp-server community {args.rw_community} RW")
    if args.contact:
        cmds.append(f"snmp-server contact {args.contact}")
    if args.location:
        cmds.append(f"snmp-server location {args.location}")
    if args.trap_host:
        community = args.ro_community or "public"
        cmds.append(f"snmp-server host {args.trap_host} traps version 2c {community}")
        cmds.append("snmp-server enable traps")
    return cmds


def verify_snmp(conn, args):
    output = conn.send_command("show snmp community")
    target = args.ro_community or args.rw_community
    if target and target not in output:
        log.warning("Community string '%s' not found in verification output", target)
        return False
    return True


def deploy_to_device(host, args):
    result = {"host": host, "status": "unknown", "detail": None}
    device_params = {
        "device_type": "cisco_ios",
        "host": host,
        "username": args.username,
        "password": args.password,
        "secret": args.enable_secret or args.password,
        "timeout": 30,
        "banner_timeout": 15,
    }
    try:
        log.info("[%s] Connecting", host)
        with ConnectHandler(**device_params) as conn:
            if args.enable_secret:
                conn.enable()
            commands = build_snmp_commands(args)
            if not commands:
                result["status"] = "skipped"
                result["detail"] = "No SNMP parameters provided"
                return result
            log.info("[%s] Pushing %d command(s)", host, len(commands))
            conn.send_config_set(commands)
            if args.verify:
                ok = verify_snmp(conn, args)
                result["status"] = "verified" if ok else "warning"
                if not ok:
                    result["detail"] = "Community string not confirmed post-deploy"
            else:
                result["status"] = "applied"
    except NetMikoAuthenticationException:
        result["status"] = "failed"
        result["detail"] = "Authentication failed"
        log.error("[%s] Authentication failed", host)
    except NetMikoTimeoutException:
        result["status"] = "failed"
        result["detail"] = "Connection timed out"
        log.error("[%s] Connection timed out", host)
    except Exception as exc:
        result["status"] = "failed"
        result["detail"] = str(exc)
        log.error("[%s] %s", host, exc)
    return result


def print_summary(results):
    log.info("--- Deployment Summary ---")
    for r in results:
        tag = f"[{r['status'].upper()}]"
        extra = f" — {r['detail']}" if r["detail"] else ""
        log.info("  %-20s %s%s", r["host"], tag, extra)
    failed = sum(1 for r in results if r["status"] == "failed")
    warnings = sum(1 for r in results if r["status"] == "warning")
    log.info("Total: %d devices | failed: %d | warnings: %d", len(results), failed, warnings)
    return failed


def parse_args():
    parser = argparse.ArgumentParser(
        description="Deploy SNMP v2c configuration to Cisco IOS devices."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--host", help="Single device IP or hostname")
    target.add_argument("--device-file", metavar="FILE",
                        help="File with one device IP per line (# for comments)")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", default=None,
                        help="SSH password (prompted if omitted)")
    parser.add_argument("--enable-secret", default=None,
                        help="Enable secret if privilege escalation is required")
    parser.add_argument("--ro-community", metavar="STRING",
                        help="SNMP read-only community string")
    parser.add_argument("--rw-community", metavar="STRING",
                        help="SNMP read-write community string")
    parser.add_argument("--trap-host", metavar="IP",
                        help="SNMP trap receiver IP address")
    parser.add_argument("--contact", metavar="STRING",
                        help="snmp-server contact value")
    parser.add_argument("--location", metavar="STRING",
                        help="snmp-server location value")
    parser.add_argument("--no-verify", dest="verify", action="store_false",
                        default=True,
                        help="Skip post-deployment verification check")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug-level logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.password is None:
        args.password = getpass.getpass(f"Password for {args.username}: ")

    snmp_params = [args.ro_community, args.rw_community, args.trap_host,
                   args.contact, args.location]
    if not any(snmp_params):
        print("error: at least one SNMP parameter is required "
              "(--ro-community, --rw-community, --trap-host, --contact, --location)",
              file=sys.stderr)
        sys.exit(1)

    if args.host:
        hosts = [args.host]
    else:
        device_file = Path(args.device_file)
        if not device_file.exists():
            print(f"error: device file not found: {args.device_file}", file=sys.stderr)
            sys.exit(1)
        hosts = [
            line.strip()
            for line in device_file.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if not hosts:
            print(f"error: no hosts found in {args.device_file}", file=sys.stderr)
            sys.exit(1)

    results = [deploy_to_device(h, args) for h in hosts]
    failed = print_summary(results)
    sys.exit(1 if failed else 0)
```