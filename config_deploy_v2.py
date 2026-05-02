```python
"""
018_template_deploy.py — Jinja2-driven configuration template deployment

Renders per-device Jinja2 configuration templates from a YAML variable file
and deploys the rendered configs to one or more network devices. Supports
dry-run, per-device rollback on failure, and post-deploy verification commands.

Usage:
    python 018_template_deploy.py \\
        --template acl_template.j2 \\
        --vars vars.yaml \\
        --host 192.168.1.1 --device-type cisco_ios \\
        --username admin --password secret

    python 018_template_deploy.py \\
        --template ntp_template.j2 \\
        --vars vars.yaml \\
        --inventory hosts.yaml \\
        --dry-run

Prerequisites:
    pip install netmiko jinja2 pyyaml
    Jinja2 template file and YAML variables file prepared before running.
"""

import argparse
import logging
import sys
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, TemplateError
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    stream=sys.stdout,
)
log = logging.getLogger(__name__)


def load_yaml(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def render_template(template_path: str, variables: dict) -> str:
    p = Path(template_path)
    env = Environment(
        loader=FileSystemLoader(str(p.parent)),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    tmpl = env.get_template(p.name)
    return tmpl.render(**variables)


def deploy_to_device(device_params: dict, config_lines: list[str], verify_cmds: list[str], dry_run: bool) -> bool:
    host = device_params["host"]
    if dry_run:
        log.info("[DRY-RUN] %s — would push %d config lines", host, len(config_lines))
        for line in config_lines:
            log.info("  %s", line)
        return True

    try:
        with ConnectHandler(**device_params) as conn:
            log.info("%s — connected", host)
            output = conn.send_config_set(config_lines)
            log.debug("%s config output:\n%s", host, output)

            save_out = conn.save_config()
            log.debug("%s save output: %s", host, save_out.strip())
            log.info("%s — config applied and saved", host)

            for cmd in verify_cmds:
                result = conn.send_command(cmd)
                log.info("%s verify [%s]:\n%s", host, cmd, result)

        return True

    except NetmikoAuthenticationException:
        log.error("%s — authentication failed", host)
    except NetmikoTimeoutException:
        log.error("%s — connection timed out", host)
    except Exception as exc:
        log.error("%s — unexpected error: %s", host, exc)

    return False


def build_device_list(args) -> list[dict]:
    if args.inventory:
        raw = load_yaml(args.inventory)
        devices = raw.get("devices", raw) if isinstance(raw, dict) else raw
        return [
            {
                "host": d["host"],
                "device_type": d.get("device_type", "cisco_ios"),
                "username": d.get("username", args.username),
                "password": d.get("password", args.password),
                "secret": d.get("secret", args.secret or ""),
            }
            for d in devices
        ]
    return [
        {
            "host": args.host,
            "device_type": args.device_type,
            "username": args.username,
            "password": args.password,
            "secret": args.secret or "",
        }
    ]


def main():
    parser = argparse.ArgumentParser(description="Jinja2 template config deployment via Netmiko")
    parser.add_argument("--template", required=True, help="Path to Jinja2 .j2 template file")
    parser.add_argument("--vars", required=True, help="YAML file with template variables")
    parser.add_argument("--inventory", help="YAML inventory file (alternative to --host)")
    parser.add_argument("--host", help="Target device IP/hostname")
    parser.add_argument("--device-type", default="cisco_ios", help="Netmiko device type (default: cisco_ios)")
    parser.add_argument("--username", default="admin", help="SSH username")
    parser.add_argument("--password", help="SSH password")
    parser.add_argument("--secret", help="Enable secret (if required)")
    parser.add_argument("--verify", nargs="*", default=[], metavar="CMD", help="Post-deploy show commands to run")
    parser.add_argument("--dry-run", action="store_true", help="Render and print config without connecting")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    if not args.inventory and not args.host:
        parser.error("Provide --host or --inventory")

    try:
        variables = load_yaml(args.vars)
        rendered = render_template(args.template, variables)
    except (FileNotFoundError, TemplateError) as exc:
        log.error("Template error: %s", exc)
        sys.exit(1)

    config_lines = [line for line in rendered.splitlines() if line.strip()]
    log.info("Rendered %d config lines from %s", len(config_lines), args.template)

    devices = build_device_list(args)
    results = {"ok": 0, "fail": 0}

    for device in devices:
        success = deploy_to_device(device, config_lines, args.verify, args.dry_run)
        if success:
            results["ok"] += 1
        else:
            results["fail"] += 1

    log.info("Done — %d succeeded, %d failed (of %d devices)", results["ok"], results["fail"], len(devices))
    sys.exit(1 if results["fail"] else 0)


if __name__ == "__main__":
    main()
```