mac_aware_port_bounce.py - Port bounce with MAC address tracking and reconnection verification.

Purpose:
    Bounces one or more switch ports while recording connected MAC addresses
    before shutdown, then polls the forwarding table until those MACs reappear
    or a timeout expires. Confirms devices reconnect cleanly after forced
    re-authentication, cable remediation, or 802.1X reauthentication cycles.

Usage:
    python mac_aware_port_bounce.py -d 192.168.1.1 -u admin -p secret \
        -i GigabitEthernet0/1 GigabitEthernet0/2 \
        [--wait 10] [--timeout 90] [--device-type cisco_ios] [--secret enable]

Prerequisites:
    pip install netmiko
    Device must support: show mac address-table interface <intf>
    SSH credentials must have privilege to enter config mode (shut/no shut).
"""

import argparse
import logging
import re
import sys
import time

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

MAC_RE = re.compile(r"[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}", re.I)


def get_interface_macs(conn, interface):
    output = conn.send_command(f"show mac address-table interface {interface}")
    return set(MAC_RE.findall(output))


def get_interface_status(conn, interface):
    output = conn.send_command(f"show interfaces {interface} | include line protocol")
    return "up" if "up" in output.lower() else "down"


def bounce_interface(conn, interface, wait_seconds):
    log.info("Shutting %s", interface)
    conn.send_config_set([f"interface {interface}", "shutdown"])
    time.sleep(wait_seconds)
    log.info("Restoring %s after %ds", interface, wait_seconds)
    conn.send_config_set([f"interface {interface}", "no shutdown"])


def wait_for_macs(conn, interface, expected, timeout, poll=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        current = get_interface_macs(conn, interface)
        missing = expected - current
        if not missing:
            return expected & current, set()
        log.debug("%s: %d/%d MACs back, continuing to poll", interface, len(expected) - len(missing), len(expected))
        time.sleep(poll)
    current = get_interface_macs(conn, interface)
    return expected & current, expected - current


def process_interface(conn, interface, wait_seconds, mac_timeout):
    result = {
        "interface": interface,
        "status": "unknown",
        "pre_macs": set(),
        "recovered": set(),
        "missing": set(),
    }

    status = get_interface_status(conn, interface)
    if status != "up":
        log.warning("%s not up (status: %s) — skipping", interface, status)
        result["status"] = f"skipped:{status}"
        return result

    pre_macs = get_interface_macs(conn, interface)
    result["pre_macs"] = pre_macs
    log.info("%s: %d MAC(s) before bounce: %s", interface, len(pre_macs), pre_macs or "none")

    bounce_interface(conn, interface, wait_seconds)

    if not pre_macs:
        result["status"] = "bounced:no_macs"
        log.info("%s: bounce complete (no MACs to track)", interface)
        return result

    log.info("%s: polling up to %ds for %d MAC(s)", interface, mac_timeout, len(pre_macs))
    recovered, missing = wait_for_macs(conn, interface, pre_macs, mac_timeout)
    result["recovered"] = recovered
    result["missing"] = missing

    if missing:
        result["status"] = "incomplete"
        log.warning("%s: %d MAC(s) did not return: %s", interface, len(missing), missing)
    else:
        result["status"] = "success"
        log.info("%s: all %d MAC(s) recovered", interface, len(recovered))

    return result


def print_summary(results):
    width = 60
    print("\n" + "=" * width)
    print("PORT BOUNCE SUMMARY")
    print("=" * width)
    for r in results:
        print(f"\n  Interface : {r['interface']}")
        print(f"  Status    : {r['status']}")
        print(f"  Pre-MACs  : {', '.join(sorted(r['pre_macs'])) or 'none'}")
        if r["pre_macs"]:
            print(f"  Recovered : {', '.join(sorted(r['recovered'])) or 'none'}")
        if r["missing"]:
            print(f"  MISSING   : {', '.join(sorted(r['missing']))}")
    print("=" * width)


def parse_args():
    p = argparse.ArgumentParser(
        description="Bounce switch ports and verify connected devices reconnect via MAC tracking."
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument("-i", "--interfaces", required=True, nargs="+", metavar="INTF",
                   help="One or more interfaces to bounce")
    p.add_argument("--device-type", default="cisco_ios",
                   help="Netmiko device type (default: cisco_ios)")
    p.add_argument("--wait", type=int, default=10,
                   help="Seconds to hold port down (default: 10)")
    p.add_argument("--timeout", type=int, default=90,
                   help="Seconds to wait for MACs to return (default: 90)")
    p.add_argument("--secret", default="", help="Enable secret for privileged mode")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "secret": args.secret,
    }

    log.info("Connecting to %s", args.device)
    try:
        conn = ConnectHandler(**params)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.device)
        sys.exit(1)
    except NetmikoTimeoutException:
        log.error("Connection timed out for %s", args.device)
        sys.exit(1)

    if args.secret:
        conn.enable()

    results = []
    try:
        for intf in args.interfaces:
            log.info("--- %s ---", intf)
            results.append(process_interface(conn, intf, args.wait, args.timeout))
    finally:
        conn.disconnect()
        log.info("Disconnected from %s", args.device)

    print_summary(results)
    failed = [r for r in results if r["status"] in ("incomplete", "unknown")]
    sys.exit(1 if failed else 0)