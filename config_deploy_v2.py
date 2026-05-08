vlan_provisioner.py - Batch VLAN provisioning for Cisco IOS switches.

Purpose:
    Read VLAN definitions from a YAML file and deploy them to a Cisco IOS
    switch via Netmiko. Creates VLANs, assigns interfaces as access or trunk,
    then verifies each VLAN is active in the VLAN database post-deployment.

Usage:
    python vlan_provisioner.py -d 192.168.1.1 -u admin -p secret -f vlans.yaml
    python vlan_provisioner.py -d 192.168.1.1 -u admin -p secret -f vlans.yaml --dry-run

YAML format (vlans.yaml):
    vlans:
      - id: 100
        name: MANAGEMENT
        interfaces:
          - name: GigabitEthernet0/1
            mode: access
          - name: GigabitEthernet0/2
            mode: trunk
      - id: 200
        name: VOICE
        interfaces: []

Prerequisites:
    pip install netmiko pyyaml
"""

import argparse
import logging
import sys

import yaml
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def load_vlan_definitions(filepath):
    with open(filepath) as fh:
        data = yaml.safe_load(fh)
    vlans = data.get("vlans", [])
    if not vlans:
        raise ValueError(f"No VLANs defined in {filepath}")
    for v in vlans:
        if not isinstance(v.get("id"), int) or not v.get("name"):
            raise ValueError(f"Each VLAN requires integer 'id' and string 'name': {v}")
    return vlans


def build_vlan_commands(vlan):
    cmds = [f"vlan {vlan['id']}", f"name {vlan['name']}", "exit"]
    for iface in vlan.get("interfaces", []):
        mode = iface["mode"]
        cmds.append(f"interface {iface['name']}")
        if mode == "access":
            cmds += [
                "switchport mode access",
                f"switchport access vlan {vlan['id']}",
            ]
        elif mode == "trunk":
            cmds += [
                "switchport mode trunk",
                f"switchport trunk allowed vlan add {vlan['id']}",
            ]
        else:
            log.warning("Unknown interface mode '%s' for %s — skipping", mode, iface["name"])
        cmds.append("exit")
    return cmds


def get_active_vlans(conn):
    output = conn.send_command("show vlan brief")
    active = set()
    for line in output.splitlines():
        parts = line.split()
        if parts and parts[0].isdigit() and "active" in line:
            active.add(int(parts[0]))
    return active


def provision_vlans(conn, vlans, dry_run=False):
    results = {}
    pre_vlans = get_active_vlans(conn)
    log.info("VLANs active before deployment: %s", sorted(pre_vlans))

    for vlan in vlans:
        vid = vlan["id"]
        cmds = build_vlan_commands(vlan)
        log.info("VLAN %d (%s): %d command(s) to send", vid, vlan["name"], len(cmds))

        if dry_run:
            for cmd in cmds:
                log.info("  [dry-run] %s", cmd)
            results[vid] = "dry-run"
            continue

        output = conn.send_config_set(cmds)
        if "Invalid" in output or "Error" in output:
            log.error("VLAN %d: device returned error:\n%s", vid, output)
            results[vid] = "error"
        else:
            results[vid] = "deployed"

    if dry_run:
        return results

    conn.save_config()

    post_vlans = get_active_vlans(conn)
    log.info("VLANs active after deployment: %s", sorted(post_vlans))

    for vlan in vlans:
        vid = vlan["id"]
        if results.get(vid) != "deployed":
            continue
        if vid in post_vlans:
            results[vid] = "verified"
            log.info("VLAN %d: verified active in VLAN database", vid)
        else:
            results[vid] = "missing"
            log.warning("VLAN %d: not found in VLAN database after deployment", vid)

    return results


def parse_args():
    parser = argparse.ArgumentParser(
        description="Batch VLAN provisioning for Cisco IOS switches"
    )
    parser.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("-s", "--secret", default="", help="Enable secret")
    parser.add_argument(
        "-t", "--device-type", default="cisco_ios", help="Netmiko device type"
    )
    parser.add_argument("-f", "--file", required=True, help="YAML file with VLAN definitions")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--dry-run", action="store_true", help="Print commands without sending to device"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    try:
        vlans = load_vlan_definitions(args.file)
    except (FileNotFoundError, ValueError) as exc:
        log.error("Failed to load VLAN definitions: %s", exc)
        sys.exit(1)

    log.info("Loaded %d VLAN(s) from %s", len(vlans), args.file)
    if args.dry_run:
        log.info("Dry-run mode — no changes will be sent to device")

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "secret": args.secret,
        "port": args.port,
    }

    try:
        log.info("Connecting to %s", args.device)
        with ConnectHandler(**device_params) as conn:
            if args.secret:
                conn.enable()
            results = provision_vlans(conn, vlans, dry_run=args.dry_run)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", args.device)
        sys.exit(1)
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        sys.exit(1)

    verified = sum(1 for s in results.values() if s == "verified")
    dry = sum(1 for s in results.values() if s == "dry-run")
    errors = sum(1 for s in results.values() if s in ("error", "missing"))

    log.info(
        "Summary: %d verified, %d dry-run, %d error(s) | total: %d VLAN(s)",
        verified, dry, errors, len(results),
    )
    sys.exit(0 if errors == 0 else 1)