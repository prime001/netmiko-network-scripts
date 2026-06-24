arp_table_collector.py — Collect and search ARP tables across network devices.

Purpose:
    Connects to one or more routers or Layer-3 switches via SSH and retrieves
    their ARP tables. Results can be filtered by IP or MAC address and exported
    to CSV for IP-to-MAC inventory or endpoint troubleshooting.

Usage:
    # Full ARP table from one device
    python arp_table_collector.py --host 192.168.1.1 --username admin --password s3cr3t

    # Search for an IP across a fleet (one host per line in devices.txt)
    python arp_table_collector.py --hosts-file devices.txt --username admin \\
        --password s3cr3t --search-ip 10.0.0.50

    # Filter by partial MAC and write results to CSV
    python arp_table_collector.py --host 192.168.1.1 --username admin --password s3cr3t \\
        --search-mac "00:1a:2b" --output arp_results.csv

    Hosts file format (one per line):
        192.168.1.1 cisco_ios
        10.0.0.1 cisco_nxos
        172.16.0.1              # defaults to --device-type if no type given

Prerequisites:
    pip install netmiko
"""

import argparse
import csv
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

_CISCO_ARP_RE = re.compile(
    r"Internet\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\S+)",
    re.IGNORECASE,
)
_JUNOS_ARP_RE = re.compile(
    r"([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})"
    r"\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)",
    re.IGNORECASE,
)

PLATFORM_CONFIG = {
    "cisco_ios":  {"command": "show ip arp",       "parser": "cisco"},
    "cisco_nxos": {"command": "show ip arp",       "parser": "cisco"},
    "cisco_xr":   {"command": "show arp",          "parser": "cisco"},
    "juniper_junos": {"command": "show arp no-resolve", "parser": "junos"},
}


def _normalize_mac(raw: str) -> str:
    digits = re.sub(r"[^0-9a-fA-F]", "", raw)
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).lower()


def _parse_cisco(output: str) -> list[dict]:
    return [
        {"ip": m.group(1), "mac": _normalize_mac(m.group(2)), "interface": m.group(3)}
        for m in _CISCO_ARP_RE.finditer(output)
    ]


def _parse_junos(output: str) -> list[dict]:
    return [
        {"ip": m.group(2), "mac": _normalize_mac(m.group(1)), "interface": m.group(3)}
        for m in _JUNOS_ARP_RE.finditer(output)
    ]


def collect_arp(host: str, username: str, password: str, device_type: str) -> list[dict]:
    if device_type not in PLATFORM_CONFIG:
        log.warning("Unsupported device type '%s' for %s — skipping", device_type, host)
        return []

    cfg = PLATFORM_CONFIG[device_type]
    try:
        with ConnectHandler(
            device_type=device_type,
            host=host,
            username=username,
            password=password,
            timeout=30,
        ) as conn:
            log.info("Connected to %s (%s)", host, device_type)
            output = conn.send_command(cfg["command"])

        entries = _parse_cisco(output) if cfg["parser"] == "cisco" else _parse_junos(output)
        for e in entries:
            e["device"] = host
        log.info("  %d entries from %s", len(entries), host)
        return entries

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", host)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", host)
    except Exception as exc:
        log.error("Unexpected error on %s: %s", host, exc)
    return []


def filter_entries(
    entries: list[dict],
    search_ip: str | None,
    search_mac: str | None,
) -> list[dict]:
    if search_ip:
        entries = [e for e in entries if e["ip"] == search_ip]
    if search_mac:
        needle = re.sub(r"[^0-9a-fA-F]", "", search_mac).lower()
        entries = [e for e in entries if needle in e["mac"].replace(":", "")]
    return entries


def load_hosts(path: str, default_type: str) -> list[tuple[str, str]]:
    hosts = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            hosts.append((parts[0], parts[1] if len(parts) > 1 else default_type))
    return hosts


def write_csv(entries: list[dict], path: str) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["device", "ip", "mac", "interface"])
        writer.writeheader()
        writer.writerows(entries)
    log.info("Results written to %s", path)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Collect ARP tables from network devices via SSH.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("--host", help="Single device IP or hostname")
    target.add_argument("--hosts-file", metavar="FILE",
                        help="File with one host per line (host [device_type])")
    p.add_argument("--username", required=True)
    p.add_argument("--password", help="SSH password (prompted if omitted)")
    p.add_argument("--device-type", default="cisco_ios",
                   choices=list(PLATFORM_CONFIG),
                   help="Netmiko device type (default: cisco_ios)")
    p.add_argument("--search-ip", metavar="IP",
                   help="Return only entries matching this IP address")
    p.add_argument("--search-mac", metavar="MAC",
                   help="Return entries whose MAC contains this substring (any notation)")
    p.add_argument("--output", metavar="FILE",
                   help="Write results to CSV")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    password = args.password or getpass(f"Password for {args.username}: ")

    if args.host:
        targets = [(args.host, args.device_type)]
    else:
        try:
            targets = load_hosts(args.hosts_file, args.device_type)
        except FileNotFoundError:
            log.error("Hosts file not found: %s", args.hosts_file)
            sys.exit(1)

    all_entries: list[dict] = []
    for host, dtype in targets:
        all_entries.extend(collect_arp(host, args.username, password, dtype))

    results = filter_entries(all_entries, args.search_ip, args.search_mac)

    if not results:
        log.info("No matching ARP entries found.")
        sys.exit(0)

    print(f"\n{'Device':<20} {'IP Address':<18} {'MAC Address':<20} Interface")
    print("-" * 76)
    for e in results:
        print(f"{e['device']:<20} {e['ip']:<18} {e['mac']:<20} {e['interface']}")
    print(f"\nTotal: {len(results)} entr{'y' if len(results) == 1 else 'ies'}")

    if args.output:
        write_csv(results, args.output)