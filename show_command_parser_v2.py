The write was blocked by permissions. Here is the complete script — copy it into `vlan_audit.py`:

```python
"""
vlan_audit.py - VLAN inventory collector and compliance auditor for Cisco IOS/IOS-XE switches.

Purpose:
    Connects to a switch via SSH, collects the VLAN database from 'show vlan brief',
    and optionally compares it against an expected VLAN list to detect configuration drift.
    Exits with code 2 when a compliance check fails, making it CI/CD pipeline friendly.

Usage:
    python vlan_audit.py -d 192.168.1.1 -u admin -p secret
    python vlan_audit.py -d 192.168.1.1 -u admin -p secret --expected vlans.txt
    python vlan_audit.py -d 192.168.1.1 -u admin -p secret --output report.json --json

Prerequisites:
    pip install netmiko
    SSH access with privilege level sufficient to run 'show vlan brief'.

Expected VLAN file format (vlans.txt):
    One VLAN ID per line. Lines starting with # are treated as comments.
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timezone

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def parse_vlan_brief(output: str) -> dict:
    """Return dict keyed by int VLAN ID from 'show vlan brief' output."""
    vlans = {}
    vlan_line = re.compile(
        r"^(\d+)\s+(\S+)\s+(active|act/lshut|act/unsup|suspended|sus/lshut)\s*(.*)?$",
        re.MULTILINE,
    )
    continuation = re.compile(r"^\s{21,}(.+)$")

    last_id = None
    for line in output.splitlines():
        m = vlan_line.match(line)
        if m:
            vid = int(m.group(1))
            ports = [p.strip() for p in m.group(4).split(",") if p.strip()]
            vlans[vid] = {"name": m.group(2), "status": m.group(3), "ports": ports}
            last_id = vid
        elif last_id is not None:
            c = continuation.match(line)
            if c:
                extra = [p.strip() for p in c.group(1).split(",") if p.strip()]
                vlans[last_id]["ports"].extend(extra)

    return vlans


def load_expected_vlans(path: str) -> set:
    """Load expected VLAN IDs from a file, one per line, # comments ignored."""
    expected = set()
    with open(path) as fh:
        for raw in fh:
            line = raw.split("#")[0].strip()
            if not line:
                continue
            try:
                expected.add(int(line))
            except ValueError:
                logger.warning("Ignoring non-integer VLAN entry: %r", line)
    return expected


def run_audit(discovered: dict, expected: set) -> dict:
    found = set(discovered)
    return {
        "missing": sorted(expected - found),
        "unexpected": sorted(found - expected),
        "compliant": sorted(found & expected),
    }


def collect(args) -> dict:
    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }
    if args.enable_secret:
        device_params["secret"] = args.enable_secret

    logger.info("Connecting to %s", args.device)
    try:
        with ConnectHandler(**device_params) as conn:
            if args.enable_secret:
                conn.enable()
            logger.info("Running 'show vlan brief'")
            raw = conn.send_command("show vlan brief")
    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s", args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        logger.error("Connection timed out to %s", args.device)
        sys.exit(1)

    vlans = parse_vlan_brief(raw)
    logger.info("Discovered %d VLANs", len(vlans))

    result = {
        "device": args.device,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "vlans": {str(k): v for k, v in sorted(vlans.items())},
    }

    if args.expected:
        expected_set = load_expected_vlans(args.expected)
        result["audit"] = run_audit(vlans, expected_set)
        missing = result["audit"]["missing"]
        unexpected = result["audit"]["unexpected"]
        if missing:
            logger.warning("Missing VLANs (expected but absent): %s", missing)
        if unexpected:
            logger.warning("Unexpected VLANs (present but not expected): %s", unexpected)
        if not missing and not unexpected:
            logger.info("VLAN inventory is fully compliant")

    return result


def print_table(result: dict) -> None:
    print(f"\nVLAN Report  —  {result['device']}  @  {result['timestamp']}")
    print("=" * 70)
    print(f"{'VLAN':<6} {'Name':<22} {'Status':<14} Ports")
    print("-" * 70)
    for vid, info in result["vlans"].items():
        ports = ", ".join(info["ports"]) if info["ports"] else "(unassigned)"
        print(f"{vid:<6} {info['name']:<22} {info['status']:<14} {ports}")

    if "audit" not in result:
        return

    audit = result["audit"]
    print("\nCompliance Check")
    print("-" * 40)
    print(f"  Compliant  : {len(audit['compliant'])} VLANs")
    if audit["missing"]:
        print(f"  MISSING    : {audit['missing']}")
    if audit["unexpected"]:
        print(f"  UNEXPECTED : {audit['unexpected']}")
    status = "PASS" if not audit["missing"] and not audit["unexpected"] else "FAIL"
    print(f"  Result     : {status}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Collect and audit VLAN inventory from Cisco IOS/IOS-XE switches."
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("-e", "--enable-secret", metavar="SECRET", help="Enable secret")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument(
        "--expected", metavar="FILE",
        help="File of expected VLAN IDs for compliance check (one per line)",
    )
    p.add_argument("--output", metavar="FILE", help="Write JSON report to this path")
    p.add_argument("--json", action="store_true", help="Print JSON instead of table")
    p.add_argument("--debug", action="store_true", help="Enable debug logging")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    result = collect(args)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_table(result)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(result, fh, indent=2)
        logger.info("Report written to %s", args.output)

    if "audit" in result:
        audit = result["audit"]
        if audit["missing"] or audit["unexpected"]:
            sys.exit(2)
```

The script is a VLAN audit tool — distinct from the existing show_command_parser scripts. Key design choices:

- **`parse_vlan_brief`** handles multi-line port lists (Cisco wraps long port lists onto continuation lines with 21+ leading spaces)
- **Compliance mode** (`--expected vlans.txt`) diffs discovered vs expected VLANs and exits 2 on failure, so it integrates cleanly into automated checks or Ansible playbooks
- **Dual output** — human-readable table by default, `--json` for machine consumption, `--output` to write both
- **`run_audit` returns `missing`, `unexpected`, and `compliant`** separately so the caller (or a consuming script) can act on each category independently