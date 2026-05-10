```python
"""vlan_audit.py — Multi-switch VLAN consistency auditor

Purpose:
    Connects to one or more switches, collects VLAN databases and trunk
    assignments, and reports VLANs that are missing from some switches.
    Optionally compares against a saved JSON baseline to detect drift.

Usage:
    python vlan_audit.py --hosts 10.0.0.1 10.0.0.2 --username admin
    python vlan_audit.py --hosts-file switches.txt --username admin \\
        --baseline vlans_baseline.json
    python vlan_audit.py --hosts 10.0.0.1 --username admin \\
        --save-baseline vlans_baseline.json

Prerequisites:
    pip install netmiko
    Devices must support 'show vlan brief' and 'show interfaces trunk'
"""

import argparse
import json
import logging
import sys
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


def parse_vlan_brief(output):
    """Return {vlan_id: name} from 'show vlan brief' output."""
    vlans = {}
    for line in output.splitlines():
        parts = line.split()
        if parts and parts[0].isdigit():
            vlans[int(parts[0])] = parts[1] if len(parts) > 1 else ""
    return vlans


def parse_trunk_interfaces(output):
    """Return list of trunking interface names from 'show interfaces trunk'."""
    trunks = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] in ("trunking", "802.1q"):
            trunks.append(parts[0])
    return trunks


def collect_device_vlans(host, device_type, username, password, port):
    """Connect to a device and return its VLAN and trunk data, or None on failure."""
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
    }
    try:
        log.info("Connecting to %s", host)
        with ConnectHandler(**params) as conn:
            vlan_output = conn.send_command("show vlan brief")
            trunk_output = conn.send_command("show interfaces trunk")
            return {
                "vlans": parse_vlan_brief(vlan_output),
                "trunks": parse_trunk_interfaces(trunk_output),
            }
    except NetmikoAuthenticationException:
        log.error("Authentication failed: %s", host)
    except NetmikoTimeoutException:
        log.error("Connection timed out: %s", host)
    except Exception as exc:
        log.error("Error on %s: %s", host, exc)
    return None


def build_report(results, baseline=None):
    """Cross-reference VLANs across all reachable devices."""
    reachable = {h: d for h, d in results.items() if d is not None}
    all_vlan_ids = set()
    for data in reachable.values():
        all_vlan_ids.update(data["vlans"].keys())

    report = {"all_vlans": sorted(all_vlan_ids), "devices": {}}

    for host, data in results.items():
        if data is None:
            report["devices"][host] = {"error": "unreachable"}
            continue

        device_vlans = set(data["vlans"].keys())
        entry = {
            "vlan_count": len(device_vlans),
            "trunk_count": len(data["trunks"]),
            "missing_vlans": sorted(all_vlan_ids - device_vlans),
        }

        if baseline:
            baseline_vlans = set(baseline.get("vlans", []))
            entry["added_since_baseline"] = sorted(device_vlans - baseline_vlans)
            entry["removed_since_baseline"] = sorted(baseline_vlans - device_vlans)

        report["devices"][host] = entry

    return report


def print_report(report):
    divider = "=" * 60
    print(f"\n{divider}")
    print("VLAN AUDIT REPORT")
    print(divider)
    print(f"Total unique VLANs across all devices: {len(report['all_vlans'])}")
    print(f"VLANs present: {report['all_vlans']}\n")

    for host, dev in report["devices"].items():
        print(f"  {host}")
        if "error" in dev:
            print(f"    ERROR: {dev['error']}")
            continue
        print(f"    VLANs: {dev['vlan_count']}  Trunks: {dev['trunk_count']}")
        missing = dev["missing_vlans"]
        print(f"    Missing from this device: {missing if missing else 'none'}")
        if "added_since_baseline" in dev:
            added = dev["added_since_baseline"]
            removed = dev["removed_since_baseline"]
            if added:
                print(f"    Added since baseline:   {added}")
            if removed:
                print(f"    Removed since baseline: {removed}")

    print(divider + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Audit VLAN consistency across multiple switches"
    )
    host_group = parser.add_mutually_exclusive_group(required=True)
    host_group.add_argument("--hosts", nargs="+", metavar="HOST",
                            help="Device IP(s) or hostnames")
    host_group.add_argument("--hosts-file", metavar="FILE",
                            help="File with one host per line (# for comments)")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", default=None,
                        help="Prompt if omitted")
    parser.add_argument("--device-type", default="cisco_ios",
                        help="Netmiko device type (default: cisco_ios)")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--baseline", metavar="FILE",
                        help="JSON baseline file to compare against")
    parser.add_argument("--save-baseline", metavar="FILE",
                        help="Save current VLAN union to a JSON baseline file")
    parser.add_argument("--json-out", metavar="FILE",
                        help="Write full report to a JSON file")
    args = parser.parse_args()

    password = args.password or getpass(f"Password for {args.username}: ")

    if args.hosts_file:
        with open(args.hosts_file) as fh:
            hosts = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    else:
        hosts = args.hosts

    baseline = None
    if args.baseline:
        with open(args.baseline) as fh:
            baseline = json.load(fh)
        log.info("Loaded baseline from %s (%d VLANs)", args.baseline,
                 len(baseline.get("vlans", [])))

    results = {
        host: collect_device_vlans(host, args.device_type, args.username,
                                   password, args.port)
        for host in hosts
    }

    report = build_report(results, baseline)
    print_report(report)

    if args.save_baseline:
        all_vlans = sorted({v for d in results.values() if d for v in d["vlans"]})
        with open(args.save_baseline, "w") as fh:
            json.dump({"vlans": all_vlans, "devices": hosts}, fh, indent=2)
        log.info("Baseline saved to %s", args.save_baseline)

    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(report, fh, indent=2)
        log.info("Report written to %s", args.json_out)

    unreachable = sum(1 for d in report["devices"].values() if "error" in d)
    sys.exit(1 if unreachable else 0)


if __name__ == "__main__":
    main()
```