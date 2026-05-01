015_vlan_audit.py — VLAN Consistency Audit Across Switches

Purpose:
    Connects to multiple Cisco/Arista switches and audits VLAN consistency
    across the fleet. Identifies VLANs present on some switches but missing
    from others, and flags access ports assigned to VLANs not in the local
    database (orphan ports).

Usage:
    python 015_vlan_audit.py --hosts 10.0.0.1 10.0.0.2 --username admin
    python 015_vlan_audit.py --inventory switches.txt --username admin --password s3cr3t
    python 015_vlan_audit.py --hosts 10.0.0.1 --username admin --report audit.json

Prerequisites:
    pip install netmiko
    SSH access to switches with at least read-only privilege.
    Tested against Cisco IOS 15.x+, IOS-XE 16.x+, and Arista EOS 4.x.
"""

import argparse
import getpass
import json
import logging
import sys
from pathlib import Path

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

SUPPORTED_DEVICE_TYPES = ["cisco_ios", "cisco_xe", "cisco_nxos", "arista_eos"]


def parse_vlan_brief(output: str) -> dict:
    """Return {vlan_id: name} from 'show vlan brief' output."""
    vlans = {}
    for line in output.splitlines():
        parts = line.split()
        if not parts or not parts[0].isdigit():
            continue
        vlan_id = int(parts[0])
        if 1 <= vlan_id <= 4094:
            vlans[vlan_id] = parts[1] if len(parts) > 1 else ""
    return vlans


def parse_interface_status(output: str) -> dict:
    """Return {interface: vlan_id} for access ports from 'show interfaces status'."""
    ports = {}
    for line in output.splitlines():
        parts = line.split()
        if not parts or not parts[0][0:2].isalpha():
            continue
        if len(parts) >= 4 and parts[3].isdigit():
            ports[parts[0]] = int(parts[3])
    return ports


def audit_device(host: str, username: str, password: str, device_type: str) -> dict:
    """Connect to one switch and collect VLAN + interface data."""
    result = {"host": host, "vlans": {}, "ports": {}, "error": None}
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "timeout": 30,
    }
    try:
        log.info("Connecting to %s", host)
        with ConnectHandler(**params) as conn:
            vlan_out = conn.send_command("show vlan brief")
            intf_out = conn.send_command("show interfaces status")
        result["vlans"] = parse_vlan_brief(vlan_out)
        result["ports"] = parse_interface_status(intf_out)
        log.info(
            "%s: %d VLANs, %d access ports",
            host,
            len(result["vlans"]),
            len(result["ports"]),
        )
    except NetmikoAuthenticationException:
        result["error"] = "authentication failed"
        log.error("%s: authentication failed", host)
    except NetmikoTimeoutException:
        result["error"] = "connection timed out"
        log.error("%s: connection timed out", host)
    except Exception as exc:
        result["error"] = str(exc)
        log.error("%s: %s", host, exc)
    return result


def build_report(results: list) -> dict:
    """Cross-reference VLAN databases and build the audit report."""
    reachable = {r["host"]: r for r in results if not r["error"]}
    all_vlans = set()
    for r in reachable.values():
        all_vlans.update(r["vlans"])

    missing_vlans = {}
    orphan_ports = {}
    vlan_matrix = {}

    for vlan in sorted(all_vlans):
        vlan_matrix[vlan] = {
            host: "present" if vlan in data["vlans"] else "MISSING"
            for host, data in reachable.items()
        }

    for host, data in reachable.items():
        gap = sorted(all_vlans - set(data["vlans"]))
        if gap:
            missing_vlans[host] = gap
        orphans = [
            {"port": p, "vlan": v}
            for p, v in data["ports"].items()
            if v not in data["vlans"]
        ]
        if orphans:
            orphan_ports[host] = orphans

    return {
        "summary": {
            "switches_audited": len(results),
            "reachable": len(reachable),
            "failed": len(results) - len(reachable),
            "union_vlan_count": len(all_vlans),
        },
        "failed_hosts": [r["host"] for r in results if r["error"]],
        "missing_vlans": missing_vlans,
        "orphan_ports": orphan_ports,
        "vlan_matrix": vlan_matrix,
    }


def print_report(report: dict) -> None:
    s = report["summary"]
    print("\n=== VLAN Audit Report ===")
    print(f"Switches audited : {s['switches_audited']}")
    print(f"Reachable        : {s['reachable']}")
    print(f"Failed           : {s['failed']}")
    print(f"Union VLAN count : {s['union_vlan_count']}")

    if report["failed_hosts"]:
        print("\n[FAILED HOSTS]")
        for h in report["failed_hosts"]:
            print(f"  {h}")

    if report["missing_vlans"]:
        print("\n[MISSING VLANs] VLANs present on at least one peer but absent here:")
        for host, vlans in report["missing_vlans"].items():
            print(f"  {host}: {vlans}")
    else:
        print("\n[OK] VLAN databases are consistent across all reachable switches.")

    if report["orphan_ports"]:
        print("\n[ORPHAN PORTS] Access ports assigned to VLANs not in local database:")
        for host, ports in report["orphan_ports"].items():
            for entry in ports:
                print(f"  {host}  {entry['port']}  VLAN {entry['vlan']}")
    else:
        print("[OK] No orphan access ports found.")


def load_hosts(args: argparse.Namespace) -> list:
    if args.inventory:
        path = Path(args.inventory)
        if not path.exists():
            log.error("Inventory file not found: %s", args.inventory)
            sys.exit(1)
        return [
            line.strip()
            for line in path.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
    return args.hosts


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit VLAN consistency across multiple switches."
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--hosts", nargs="+", metavar="IP")
    src.add_argument("--inventory", metavar="FILE", help="One IP per line")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", help="Prompted if omitted")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=SUPPORTED_DEVICE_TYPES,
        metavar="TYPE",
        help=f"Netmiko device type (default: cisco_ios). Choices: {', '.join(SUPPORTED_DEVICE_TYPES)}",
    )
    parser.add_argument("--report", metavar="FILE", help="Save JSON report to file")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    hosts = load_hosts(args)
    if not hosts:
        log.error("No hosts to audit.")
        sys.exit(1)

    password = args.password or getpass.getpass(f"Password for {args.username}: ")
    results = [audit_device(h, args.username, password, args.device_type) for h in hosts]
    report = build_report(results)
    print_report(report)

    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2))
        log.info("JSON report saved to %s", args.report)

    has_issues = report["missing_vlans"] or report["orphan_ports"] or report["failed_hosts"]
    sys.exit(1 if has_issues else 0)


if __name__ == "__main__":
    main()