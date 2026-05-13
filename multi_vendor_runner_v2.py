```python
"""
mac_tracer.py - MAC Address to Switch Port Tracer

Locates a MAC address (or resolves an IP via ARP then locates the MAC)
across one or more switches by querying CAM tables over SSH with netmiko.
Common use cases: finding where a rogue device is plugged in, pinpointing
a workstation's physical port, or auditing MAC table entries.

Usage:
    python mac_tracer.py --hosts 10.0.0.1,10.0.0.2 --mac 00:1a:2b:3c:4d:5e
    python mac_tracer.py --hosts 10.0.0.1 --ip 192.168.1.100
    python mac_tracer.py --inventory hosts.txt --mac aa:bb:cc:dd:ee:ff --username admin

Prerequisites:
    pip install netmiko
    SSH read access to target switches.
    Supported: cisco_ios, cisco_nxos, arista_eos, hp_comware.
"""

import argparse
import logging
import re
import sys
from getpass import getpass

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger(__name__)

MAC_COMMANDS = {
    "cisco_ios": "show mac address-table address {mac}",
    "cisco_nxos": "show mac address-table address {mac}",
    "arista_eos": "show mac address-table address {mac}",
    "hp_comware": "display mac-address {mac}",
}

ARP_COMMANDS = {
    "cisco_ios": "show arp {ip}",
    "cisco_nxos": "show ip arp {ip}",
    "arista_eos": "show arp {ip}",
    "hp_comware": "display arp {ip}",
}


def normalize_mac(mac: str) -> str:
    digits = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(digits) != 12:
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2)).lower()


def resolve_ip_to_mac(conn, device_type: str, ip: str) -> str | None:
    cmd_tpl = ARP_COMMANDS.get(device_type)
    if not cmd_tpl:
        log.warning("No ARP command defined for %s", device_type)
        return None
    output = conn.send_command(cmd_tpl.format(ip=ip))
    match = re.search(
        r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}"
        r"|[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})",
        output,
    )
    return normalize_mac(match.group(1)) if match else None


def query_mac_table(conn, device_type: str, mac: str) -> list[dict]:
    cmd_tpl = MAC_COMMANDS.get(device_type)
    if not cmd_tpl:
        log.warning("No MAC table command defined for %s", device_type)
        return []
    if device_type in ("cisco_ios", "cisco_nxos"):
        d = mac.replace(":", "")
        query_mac = f"{d[0:4]}.{d[4:8]}.{d[8:12]}"
    else:
        query_mac = mac
    output = conn.send_command(cmd_tpl.format(mac=query_mac))
    return _parse_cam(output, device_type)


def _parse_cam(output: str, device_type: str) -> list[dict]:
    results = []
    if device_type in ("cisco_ios", "cisco_nxos"):
        pat = re.compile(
            r"^\s*(\d+)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+\S+\s+(\S+)",
            re.MULTILINE,
        )
        for m in pat.finditer(output):
            results.append({"vlan": m.group(1), "mac": m.group(2), "port": m.group(3)})
    elif device_type == "arista_eos":
        pat = re.compile(
            r"^\s*(\d+)\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s+\S+\s+(\S+)",
            re.MULTILINE,
        )
        for m in pat.finditer(output):
            results.append({"vlan": m.group(1), "mac": m.group(2), "port": m.group(3)})
    elif device_type == "hp_comware":
        pat = re.compile(
            r"([0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})\s+(\d+)\s+\S+\s+(\S+)",
            re.MULTILINE,
        )
        for m in pat.finditer(output):
            results.append({"vlan": m.group(2), "mac": m.group(1), "port": m.group(3)})
    return results


def connect(host: str, username: str, password: str, device_type: str, port: int):
    return ConnectHandler(
        device_type=device_type,
        host=host,
        username=username,
        password=password,
        port=port,
        timeout=15,
    )


def load_hosts(path: str) -> list[str]:
    with open(path) as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]


def main():
    parser = argparse.ArgumentParser(
        description="Trace a MAC address or IP to its switch port."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--mac", help="MAC address to locate (any common format)")
    target.add_argument("--ip", help="IP address to resolve via ARP then locate")

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--hosts", help="Comma-separated switch IPs/hostnames")
    src.add_argument("--inventory", help="File with one host per line")

    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", help="SSH password (prompted if omitted)")
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(MAC_COMMANDS.keys()),
    )
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument(
        "--gateway",
        help="Host used for ARP resolution when --ip is given; defaults to first host",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    password = args.password or getpass(f"Password for {args.username}: ")

    hosts = (
        [h.strip() for h in args.hosts.split(",") if h.strip()]
        if args.hosts
        else load_hosts(args.inventory)
    )
    if not hosts:
        parser.error("No hosts specified.")

    mac = None
    if args.mac:
        try:
            mac = normalize_mac(args.mac)
        except ValueError as e:
            parser.error(str(e))
    else:
        gateway = args.gateway or hosts[0]
        try:
            conn = connect(gateway, args.username, password, args.device_type, args.port)
            mac = resolve_ip_to_mac(conn, args.device_type, args.ip)
            conn.disconnect()
        except (NetmikoAuthenticationException, NetmikoTimeoutException) as e:
            print(f"[ERROR] Cannot connect to gateway {gateway}: {e}", file=sys.stderr)
            sys.exit(1)
        if not mac:
            print(f"[ERROR] Could not resolve {args.ip} to a MAC address.", file=sys.stderr)
            sys.exit(1)
        print(f"Resolved {args.ip} → {mac}")

    found = False
    for host in hosts:
        log.debug("Querying %s for MAC %s", host, mac)
        try:
            conn = connect(host, args.username, password, args.device_type, args.port)
            entries = query_mac_table(conn, args.device_type, mac)
            conn.disconnect()
        except NetmikoAuthenticationException:
            print(f"[{host}] Authentication failed", file=sys.stderr)
            continue
        except NetmikoTimeoutException:
            print(f"[{host}] Connection timed out", file=sys.stderr)
            continue

        if entries:
            found = True
            for e in entries:
                print(f"[FOUND] host={host}  vlan={e['vlan']}  mac={e['mac']}  port={e['port']}")
        else:
            print(f"[    ] {host}: not found")

    if not found:
        print(f"\nMAC {mac} not found on any queried device.")
        sys.exit(2)


if __name__ == "__main__":
    main()
```