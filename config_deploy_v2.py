The target directory is `/opt/NetAutoCommitter` (this project's own repo), not a separate portfolio repo. The script should just be output as text. Here it is:

```
"""
vlan_provisioner.py - VLAN bulk provisioner for Cisco IOS/IOS-XE switches.

Adds or removes a VLAN across one or more switches and verifies the change
was applied. Designed for provisioning new VLANs across access/distribution
switch stacks during network expansions or tenant onboarding.

Usage:
    python vlan_provisioner.py --hosts 10.0.0.1 10.0.0.2 --username admin \
        --vlan-id 200 --vlan-name GUEST_WIFI --action add

    python vlan_provisioner.py --hosts-file switches.txt --username admin \
        --vlan-id 200 --action remove --dry-run

    python vlan_provisioner.py --hosts 10.0.0.1 --username admin \
        --vlan-id 200 --vlan-name MGMT --action add --device-type cisco_ios

Prerequisites:
    pip install netmiko
    SSH access to target devices with privilege level 15 or enable configured.
"""

import argparse
import getpass
import logging
import sys
from dataclasses import dataclass, field
from typing import List, Optional

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


@dataclass
class ProvisionResult:
    host: str
    success: bool
    message: str
    verified: bool = False
    errors: List[str] = field(default_factory=list)


def load_hosts_file(path: str) -> List[str]:
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def build_vlan_commands(action: str, vlan_id: int, vlan_name: Optional[str]) -> List[str]:
    if action == "add":
        cmds = [f"vlan {vlan_id}"]
        if vlan_name:
            cmds.append(f"name {vlan_name}")
        cmds.append("exit")
        return cmds
    return [f"no vlan {vlan_id}"]


def verify_vlan(conn, vlan_id: int, action: str) -> tuple[bool, str]:
    output = conn.send_command(f"show vlan id {vlan_id}", expect_string=r"#")
    if action == "add":
        present = str(vlan_id) in output and "not found" not in output.lower()
        return present, output
    absent = "not found" in output.lower() or str(vlan_id) not in output
    return absent, output


def provision_vlan(
    host: str,
    username: str,
    password: str,
    vlan_id: int,
    vlan_name: Optional[str],
    action: str,
    device_type: str,
    dry_run: bool,
) -> ProvisionResult:
    log.info("[%s] Connecting...", host)
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "timeout": 30,
        "session_timeout": 60,
    }

    try:
        with ConnectHandler(**device) as conn:
            conn.enable()
            hostname = conn.find_prompt().rstrip("#>")

            cmds = build_vlan_commands(action, vlan_id, vlan_name)

            if dry_run:
                log.info("[%s] DRY RUN — would send: %s", hostname, cmds)
                return ProvisionResult(
                    host=host,
                    success=True,
                    message=f"dry-run: would {action} vlan {vlan_id}",
                    verified=False,
                )

            log.info("[%s] Sending config: %s", hostname, cmds)
            output = conn.send_config_set(cmds)

            if "Invalid" in output or "Error" in output:
                return ProvisionResult(
                    host=host,
                    success=False,
                    message="Config error from device",
                    errors=[output],
                )

            conn.save_config()

            verified, verify_output = verify_vlan(conn, vlan_id, action)
            verb = "added" if action == "add" else "removed"
            status = "verified" if verified else "UNVERIFIED"

            log.info("[%s] VLAN %d %s (%s)", hostname, vlan_id, verb, status)
            return ProvisionResult(
                host=host,
                success=True,
                message=f"VLAN {vlan_id} {verb} on {hostname}",
                verified=verified,
                errors=[] if verified else [f"Verification failed:\n{verify_output}"],
            )

    except NetmikoAuthenticationException:
        return ProvisionResult(host=host, success=False, message="Authentication failed")
    except NetmikoTimeoutException:
        return ProvisionResult(host=host, success=False, message="Connection timed out")
    except Exception as exc:
        return ProvisionResult(host=host, success=False, message=str(exc))


def print_summary(results: List[ProvisionResult]) -> None:
    print("\n" + "=" * 60)
    print(f"{'HOST':<20} {'STATUS':<12} {'VERIFIED':<10} DETAIL")
    print("-" * 60)
    for r in results:
        status = "OK" if r.success else "FAIL"
        verified = "yes" if r.verified else ("n/a" if not r.success else "NO")
        print(f"{r.host:<20} {status:<12} {verified:<10} {r.message}")
        for err in r.errors:
            print(f"  ! {err}")
    print("=" * 60)
    ok = sum(1 for r in results if r.success)
    print(f"Result: {ok}/{len(results)} succeeded")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Provision a VLAN across one or more Cisco IOS switches"
    )
    host_group = parser.add_mutually_exclusive_group(required=True)
    host_group.add_argument("--hosts", nargs="+", metavar="IP", help="One or more device IPs")
    host_group.add_argument("--hosts-file", metavar="FILE", help="File with one IP per line")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", help="Prompted if omitted")
    parser.add_argument("--vlan-id", type=int, required=True, help="VLAN ID (1-4094)")
    parser.add_argument("--vlan-name", help="VLAN name (only applies to --action add)")
    parser.add_argument("--action", choices=["add", "remove"], default="add")
    parser.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)"
    )
    parser.add_argument("--dry-run", action="store_true", help="Show commands without applying")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if not (1 <= args.vlan_id <= 4094):
        log.error("VLAN ID must be between 1 and 4094")
        sys.exit(1)

    password = args.password or getpass.getpass(f"Password for {args.username}: ")

    hosts = args.hosts if args.hosts else load_hosts_file(args.hosts_file)
    if not hosts:
        log.error("No hosts specified")
        sys.exit(1)

    log.info(
        "Action=%s VLAN=%d name=%s devices=%d dry_run=%s",
        args.action, args.vlan_id, args.vlan_name or "(none)", len(hosts), args.dry_run,
    )

    results = []
    for host in hosts:
        result = provision_vlan(
            host=host,
            username=args.username,
            password=password,
            vlan_id=args.vlan_id,
            vlan_name=args.vlan_name,
            action=args.action,
            device_type=args.device_type,
            dry_run=args.dry_run,
        )
        results.append(result)

    print_summary(results)
    sys.exit(0 if all(r.success for r in results) else 1)
```