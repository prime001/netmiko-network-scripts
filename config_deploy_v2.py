The task says to output only script content — here it is:

```
"""
vlan_provisioner.py - Bulk VLAN provisioning via Netmiko
...
```

Wait — re-reading the instructions: **"Output ONLY the script content, no markdown fences, no explanation."** That means raw text output only. Here is the script:

---

"""
vlan_provisioner.py - Bulk VLAN provisioning via Netmiko

Purpose:
    Creates, renames, or removes VLANs on Cisco IOS/IOS-XE/NX-OS switches
    from a YAML definition file. Verifies each VLAN after apply and prints
    a pass/fail summary. Designed for batch switch provisioning workflows
    where VLANs are defined in version-controlled YAML.

Usage:
    python vlan_provisioner.py --host 10.0.0.1 --username admin --vlan-file vlans.yaml
    python vlan_provisioner.py --host 10.0.0.1 --username admin --vlan-file vlans.yaml --remove
    python vlan_provisioner.py --host 10.0.0.1 --username admin --vlan-file vlans.yaml --dry-run

Prerequisites:
    pip install netmiko pyyaml

VLAN definition file format (YAML):
    vlans:
      - id: 100
        name: CORP_USERS
      - id: 200
        name: GUEST_WIFI
      - id: 300
        name: SERVERS
"""

import argparse
import getpass
import logging
import sys

import yaml
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def load_vlan_file(path):
    with open(path) as f:
        data = yaml.safe_load(f)
    vlans = data.get("vlans", [])
    if not vlans:
        raise ValueError(f"No VLANs found in {path}")
    for v in vlans:
        if not isinstance(v.get("id"), int) or not (1 <= v["id"] <= 4094):
            raise ValueError(f"Invalid VLAN ID: {v.get('id')!r}")
        if not v.get("name"):
            raise ValueError(f"VLAN {v['id']} missing 'name'")
    return vlans


def build_add_commands(vlans):
    cmds = []
    for v in vlans:
        cmds.append(f"vlan {v['id']}")
        cmds.append(f" name {v['name']}")
    return cmds


def build_remove_commands(vlans):
    ids = ",".join(str(v["id"]) for v in vlans)
    return [f"no vlan {ids}"]


def get_existing_vlans(conn):
    output = conn.send_command("show vlan brief")
    existing = {}
    for line in output.splitlines():
        parts = line.split()
        if parts and parts[0].isdigit():
            vid = int(parts[0])
            existing[vid] = parts[1] if len(parts) > 1 else ""
    return existing


def verify_vlans(conn, vlans, remove=False):
    existing = get_existing_vlans(conn)
    results = []
    all_ok = True
    for v in vlans:
        vid = v["id"]
        if remove:
            ok = vid not in existing
            status = "removed" if ok else "STILL PRESENT"
        else:
            present = vid in existing
            name_match = present and existing[vid] == v["name"]
            ok = name_match
            if not present:
                status = "MISSING"
            elif not name_match:
                status = f"name mismatch: got {existing[vid]!r}, expected {v['name']!r}"
            else:
                status = "present"
        results.append((vid, v["name"], ok, status))
        if not ok:
            all_ok = False
    return results, all_ok


def provision_vlans(args):
    try:
        vlans = load_vlan_file(args.vlan_file)
    except (OSError, ValueError, KeyError) as exc:
        log.error("Failed to load VLAN file: %s", exc)
        return 1

    log.info("Loaded %d VLAN(s) from %s", len(vlans), args.vlan_file)

    if args.remove:
        cmds = build_remove_commands(vlans)
        action = "remove"
    else:
        cmds = build_add_commands(vlans)
        action = "add"

    if args.dry_run:
        log.info("Dry-run — commands that would be sent:")
        for c in cmds:
            print(f"  {c}")
        return 0

    device = {
        "device_type": args.device_type,
        "host": args.host,
        "port": args.port,
        "username": args.username,
        "password": args.password,
    }

    try:
        log.info("Connecting to %s:%d", args.host, args.port)
        with ConnectHandler(**device) as conn:
            log.info("Connected — applying %s commands", action)
            output = conn.send_config_set(cmds)
            log.debug("Config output:\n%s", output)

            if not args.no_save:
                conn.save_config()
                log.info("Running config saved")

            results, all_ok = verify_vlans(conn, vlans, remove=args.remove)

        print(f"\n{'VLAN':>6}  {'Name':<24}  Result")
        print("-" * 55)
        for vid, name, ok, status in results:
            marker = "OK  " if ok else "FAIL"
            print(f"{vid:>6}  {name:<24}  [{marker}] {status}")
        print()

        if all_ok:
            log.info("All %d VLAN(s) verified successfully", len(vlans))
            return 0
        else:
            failed = sum(1 for _, _, ok, _ in results if not ok)
            log.error("Verification failed for %d VLAN(s)", failed)
            return 1

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 2
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s:%d", args.host, args.port)
        return 2
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        return 2


def parse_args():
    parser = argparse.ArgumentParser(
        description="Bulk VLAN provisioner for Cisco IOS/IOS-XE/NX-OS switches",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", required=True, help="Device IP or hostname")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", help="SSH password (prompted if omitted)")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=["cisco_ios", "cisco_xe", "cisco_nxos"],
        help="Netmiko device type",
    )
    parser.add_argument("--vlan-file", required=True, metavar="FILE",
                        help="YAML file defining VLANs to provision")
    parser.add_argument("--remove", action="store_true",
                        help="Remove listed VLANs instead of adding them")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print commands without connecting to device")
    parser.add_argument("--no-save", action="store_true",
                        help="Skip 'write mem' after applying changes")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if not args.password and not args.dry_run:
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")
    sys.exit(provision_vlans(args))