vlan_provisioner.py - Bulk VLAN provisioning on Cisco IOS/IOS-XE switches.

Purpose:
    Add or remove VLANs on one or more switches with pre-check and post-verify.
    Computes the delta against the current VLAN database and applies only what is
    missing (or present), then confirms the change landed before exiting.

Usage:
    Add VLANs to a single switch:
        python vlan_provisioner.py --host 10.0.0.1 --username admin --password secret \
            --vlans 100,200,300 --names "Data,Voice,Management"

    Remove VLANs:
        python vlan_provisioner.py --host 10.0.0.1 --username admin --password secret \
            --vlans 100,200 --action remove

    Batch from CSV (columns: host,vlan_id,vlan_name,action):
        python vlan_provisioner.py --csv switches.csv --username admin --password secret

    Dry-run (show commands without applying):
        python vlan_provisioner.py --host 10.0.0.1 ... --dry-run

Prerequisites:
    pip install netmiko
    SSH must be enabled; account needs privilege 15 or enable access.
    Supported device types: cisco_ios, cisco_xe
"""

import argparse
import csv
import logging
import sys
from dataclasses import dataclass, field
from typing import Optional

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


@dataclass
class VlanTask:
    vlan_id: int
    vlan_name: Optional[str] = None
    action: str = "add"


@dataclass
class ProvisionResult:
    host: str
    applied: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def get_existing_vlans(conn) -> dict:
    """Return {vlan_id: name} for all VLANs in the device database."""
    output = conn.send_command("show vlan brief", use_textfsm=True)
    if isinstance(output, list):
        return {int(e["vlan_id"]): e["name"] for e in output}
    vlans = {}
    for line in output.splitlines():
        parts = line.split()
        if parts and parts[0].isdigit():
            vlans[int(parts[0])] = parts[1] if len(parts) > 1 else ""
    return vlans


def build_commands(task: VlanTask, existing: dict) -> list:
    if task.action == "add":
        if task.vlan_id in existing:
            return []
        cmds = [f"vlan {task.vlan_id}"]
        if task.vlan_name:
            cmds.append(f" name {task.vlan_name}")
        return cmds
    if task.action == "remove":
        if task.vlan_id not in existing:
            return []
        return [f"no vlan {task.vlan_id}"]
    return []


def provision_host(
    host: str,
    username: str,
    password: str,
    device_type: str,
    tasks: list,
    dry_run: bool,
) -> ProvisionResult:
    result = ProvisionResult(host=host)
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "timeout": 30,
    }
    try:
        log.info("[%s] Connecting...", host)
        with ConnectHandler(**params) as conn:
            existing = get_existing_vlans(conn)
            log.info("[%s] %d VLANs in database", host, len(existing))

            all_cmds = []
            pending = []
            for task in tasks:
                cmds = build_commands(task, existing)
                if not cmds:
                    log.info("[%s] VLAN %d already in desired state", host, task.vlan_id)
                    result.skipped.append(task.vlan_id)
                else:
                    all_cmds.extend(cmds)
                    pending.append(task)

            if not all_cmds:
                log.info("[%s] No changes required", host)
                return result

            if dry_run:
                log.info("[%s] DRY RUN — would send:\n%s", host, "\n".join(all_cmds))
                return result

            conn.send_config_set(all_cmds)
            conn.save_config()

            post = get_existing_vlans(conn)
            for task in pending:
                if task.action == "add" and task.vlan_id not in post:
                    msg = f"VLAN {task.vlan_id} missing after add"
                    log.error("[%s] %s", host, msg)
                    result.errors.append(msg)
                elif task.action == "remove" and task.vlan_id in post:
                    msg = f"VLAN {task.vlan_id} still present after remove"
                    log.error("[%s] %s", host, msg)
                    result.errors.append(msg)
                else:
                    log.info("[%s] VLAN %d %sd OK", host, task.vlan_id, task.action)
                    result.applied.append(task.vlan_id)

    except NetmikoAuthenticationException:
        result.errors.append("authentication failed")
        log.error("[%s] Authentication failed", host)
    except NetmikoTimeoutException:
        result.errors.append("connection timed out")
        log.error("[%s] Connection timed out", host)
    except Exception as exc:
        result.errors.append(str(exc))
        log.error("[%s] %s", host, exc)

    return result


def load_csv(path: str) -> dict:
    host_tasks: dict = {}
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            host = row["host"].strip()
            task = VlanTask(
                vlan_id=int(row["vlan_id"]),
                vlan_name=row.get("vlan_name", "").strip() or None,
                action=row.get("action", "add").strip(),
            )
            host_tasks.setdefault(host, []).append(task)
    return host_tasks


def parse_args():
    p = argparse.ArgumentParser(
        description="Add or remove VLANs on Cisco IOS/IOS-XE switches"
    )
    p.add_argument("--host", help="Device IP or hostname (single-device mode)")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=["cisco_ios", "cisco_xe"],
    )
    p.add_argument("--vlans", help="Comma-separated VLAN IDs, e.g. 100,200")
    p.add_argument("--names", help="Comma-separated names matching --vlans order")
    p.add_argument("--action", default="add", choices=["add", "remove"])
    p.add_argument("--csv", dest="csv_file", help="CSV: host,vlan_id,vlan_name,action")
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args()


def main():
    args = parse_args()

    if args.csv_file:
        host_tasks = load_csv(args.csv_file)
    elif args.host and args.vlans:
        ids = [int(v.strip()) for v in args.vlans.split(",")]
        names = [n.strip() for n in args.names.split(",")] if args.names else []
        tasks = [
            VlanTask(
                vlan_id=vid,
                vlan_name=names[i] if i < len(names) else None,
                action=args.action,
            )
            for i, vid in enumerate(ids)
        ]
        host_tasks = {args.host: tasks}
    else:
        print("Error: provide --host and --vlans, or --csv", file=sys.stderr)
        sys.exit(1)

    exit_code = 0
    for host, tasks in host_tasks.items():
        result = provision_host(
            host=host,
            username=args.username,
            password=args.password,
            device_type=args.device_type,
            tasks=tasks,
            dry_run=args.dry_run,
        )
        if result.errors:
            exit_code = 1
            log.error("[%s] Finished with errors: %s", host, result.errors)
        else:
            log.info(
                "[%s] Done — applied: %s  skipped: %s",
                host,
                result.applied,
                result.skipped,
            )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()