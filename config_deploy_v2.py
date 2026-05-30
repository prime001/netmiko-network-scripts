Writing a MAC address tracer script — this is distinct from all existing scripts and covers a real-world daily task (finding which switch port a device is plugged into).

```python
"""
mac_tracer.py — MAC address and IP-to-port tracer for Cisco IOS/IOS-XE switches.

Purpose:
    Locate where a MAC address (or IP-mapped MAC) is connected by querying the
    MAC address table and ARP table on one or more switches. Useful for
    troubleshooting, asset tracking, and security incident response.

Usage:
    # Trace a MAC address on a single switch
    python mac_tracer.py --host 192.168.1.1 --user admin --mac 00:1A:2B:3C:4D:5E

    # Trace an IP address (resolves via ARP table first, then locates port)
    python mac_tracer.py --host 192.168.1.1 --user admin --ip 10.0.0.55

    # Search across multiple switches from a file (one IP/hostname per line)
    python mac_tracer.py --hosts-file switches.txt --user admin --mac aabb.cc00.1234

Prerequisites:
    pip install netmiko
    SSH must be enabled on the target switch(es).
    For --ip tracing, the first host must be a Layer-3 device holding the ARP table.
"""

import argparse
import getpass
import logging
import re
import sys
from typing import Optional

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException


logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)


def normalize_mac(mac: str) -> str:
    """Normalize any common MAC format to Cisco dotted-quad (xxxx.xxxx.xxxx)."""
    raw = re.sub(r"[.:\-]", "", mac).lower()
    if len(raw) != 12 or not re.fullmatch(r"[0-9a-f]{12}", raw):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return f"{raw[0:4]}.{raw[4:8]}.{raw[8:12]}"


def resolve_ip_to_mac(conn, ip: str) -> Optional[str]:
    """Query ARP table on an already-open connection; return MAC or None."""
    output = conn.send_command(f"show ip arp {ip}")
    match = re.search(
        r"Internet\s+\S+\s+\S+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})",
        output,
        re.IGNORECASE,
    )
    if match:
        return match.group(1).lower()
    log.warning("IP %s not found in ARP table on %s", ip, conn.host)
    return None


def query_mac_table(conn, mac: str) -> list[dict]:
    """Return parsed MAC address table entries matching the given MAC."""
    output = conn.send_command(f"show mac address-table address {mac}")
    entries = []
    for line in output.splitlines():
        m = re.match(
            r"\s*(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(\S+)\s+(\S+)",
            line,
            re.IGNORECASE,
        )
        if m:
            entries.append(
                {
                    "vlan": m.group(1),
                    "mac": m.group(2).lower(),
                    "type": m.group(3),
                    "port": m.group(4),
                }
            )
    return entries


def trace_on_host(
    host: str,
    username: str,
    password: str,
    mac: str,
    device_type: str,
) -> list[dict]:
    """Connect to one host, query MAC table, return annotated entries."""
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
    }
    try:
        log.info("Connecting to %s ...", host)
        with ConnectHandler(**params) as conn:
            entries = query_mac_table(conn, mac)
            for e in entries:
                e["host"] = host
            if not entries:
                log.info("MAC %s not found on %s", mac, host)
            return entries
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", host)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", host)
    except Exception as exc:
        log.error("Error on %s: %s", host, exc)
    return []


def resolve_then_trace(
    host: str,
    username: str,
    password: str,
    ip: str,
    device_type: str,
) -> tuple[Optional[str], list[dict]]:
    """Single-connection ARP resolution + MAC table lookup on the same host."""
    params = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
    }
    try:
        log.info("Connecting to %s to resolve IP %s ...", host, ip)
        with ConnectHandler(**params) as conn:
            mac = resolve_ip_to_mac(conn, ip)
            if not mac:
                return None, []
            log.info("Resolved %s → %s", ip, mac)
            entries = query_mac_table(conn, mac)
            for e in entries:
                e["host"] = host
            return mac, entries
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", host)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", host)
    except Exception as exc:
        log.error("Error on %s: %s", host, exc)
    return None, []


def print_results(results: list[dict], mac: str) -> None:
    if not results:
        print(f"\nMAC {mac} not found on any queried device.")
        return
    print(f"\nResults for MAC: {mac}")
    print("-" * 62)
    print(f"{'Host':<22} {'VLAN':<8} {'Type':<12} {'Port'}")
    print("-" * 62)
    for r in results:
        print(f"{r['host']:<22} {r['vlan']:<8} {r['type']:<12} {r['port']}")
    print("-" * 62)
    print(f"  {len(results)} match(es) across {len({r['host'] for r in results})} device(s).")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Trace a MAC or IP address to a switch port.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--mac", help="MAC address to search (any common delimiter format)")
    target.add_argument("--ip", help="IP address — resolved via ARP, then traced to port")

    hosts_group = parser.add_mutually_exclusive_group(required=True)
    hosts_group.add_argument("--host", help="Single switch hostname or IP")
    hosts_group.add_argument(
        "--hosts-file",
        help="File listing switch IPs/hostnames, one per line (# comments ok)",
    )

    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--password", help="SSH password (prompted if omitted)")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass.getpass(f"Password for {args.user}: ")

    if args.mac:
        try:
            mac = normalize_mac(args.mac)
        except ValueError as exc:
            log.error(exc)
            sys.exit(1)
    else:
        mac = None

    if args.hosts_file:
        try:
            with open(args.hosts_file) as fh:
                host_list = [
                    ln.strip()
                    for ln in fh
                    if ln.strip() and not ln.startswith("#")
                ]
        except FileNotFoundError:
            log.error("Hosts file not found: %s", args.hosts_file)
            sys.exit(1)
    else:
        host_list = [args.host]

    all_results: list[dict] = []

    if args.ip:
        resolved_mac, first_results = resolve_then_trace(
            host_list[0], args.user, password, args.ip, args.device_type
        )
        if not resolved_mac:
            sys.exit(1)
        mac = resolved_mac
        all_results.extend(first_results)
        for host in host_list[1:]:
            all_results.extend(
                trace_on_host(host, args.user, password, mac, args.device_type)
            )
    else:
        for host in host_list:
            all_results.extend(
                trace_on_host(host, args.user, password, mac, args.device_type)
            )

    print_results(all_results, mac)
    sys.exit(0 if all_results else 1)


if __name__ == "__main__":
    main()
```