```python
"""
port_bounce_v3.py - MAC-tracked port bounce with re-authentication verification

Bounces one or more switchports and verifies that expected MAC addresses
re-appear on the port after link restoration. Useful for forcing 802.1X
re-authentication, clearing sticky MAC entries, or confirming endpoint
reconnection after a maintenance bounce.

Usage:
    python port_bounce_v3.py -d 192.168.1.10 -u admin -p secret \
        -i GigabitEthernet0/1 --verify-mac 00:1A:2B:3C:4D:5E

    python port_bounce_v3.py -d 192.168.1.10 -u admin -p secret \
        -i Gi0/1 Gi0/2 Gi0/3 --wait 45 --device-type cisco_ios

Prerequisites:
    pip install netmiko
    Credentials with privilege level 15 (or equivalent for other vendors).
"""

import argparse
import logging
import sys
import time

from netmiko import ConnectHandler
from netmiko.exceptions import NetMikoAuthenticationException, NetMikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def get_mac_table(conn, interface):
    """Return set of MAC addresses currently learned on the interface."""
    output = conn.send_command(
        f"show mac address-table interface {interface}",
        use_textfsm=False,
    )
    macs = set()
    for line in output.splitlines():
        parts = line.split()
        for part in parts:
            if len(part) == 14 and part.count(".") == 2:
                macs.add(part.lower())
            elif len(part) == 17 and part.count(":") == 5:
                macs.add(part.lower())
    return macs


def normalize_mac(mac):
    raw = mac.replace(":", "").replace("-", "").replace(".", "").lower()
    if len(raw) != 12:
        return None
    return ":".join(raw[i:i+2] for i in range(0, 12, 2))


def bounce_interface(conn, interface, wait_seconds):
    """Shut then no-shut an interface, return (shutdown_ok, noshut_ok)."""
    log.info("Shutting down %s", interface)
    conn.send_config_set([f"interface {interface}", "shutdown"])

    log.info("Waiting %s seconds before restoring %s", wait_seconds, interface)
    time.sleep(wait_seconds)

    log.info("Restoring %s", interface)
    conn.send_config_set([f"interface {interface}", "no shutdown"])
    return True


def verify_mac_reappears(conn, interface, target_mac, timeout, poll_interval=5):
    """Poll MAC table until target MAC re-appears or timeout expires."""
    normalized = normalize_mac(target_mac)
    if not normalized:
        log.warning("Could not normalize MAC %s; skipping verification", target_mac)
        return None

    deadline = time.time() + timeout
    log.info("Waiting up to %ss for MAC %s on %s", timeout, normalized, interface)
    while time.time() < deadline:
        current = get_mac_table(conn, interface)
        for entry in current:
            if normalize_mac(entry) == normalized:
                log.info("MAC %s confirmed on %s", normalized, interface)
                return True
        time.sleep(poll_interval)

    log.warning("MAC %s did NOT re-appear on %s within %ss", normalized, interface, timeout)
    return False


def process_interface(conn, interface, verify_macs, wait_seconds, mac_timeout):
    result = {"interface": interface, "bounced": False, "mac_results": {}}

    pre_macs = get_mac_table(conn, interface)
    log.info("Pre-bounce MACs on %s: %s", interface, pre_macs or "(none)")

    bounce_interface(conn, interface, wait_seconds)
    result["bounced"] = True

    for mac in verify_macs:
        ok = verify_mac_reappears(conn, interface, mac, mac_timeout)
        result["mac_results"][mac] = ok

    return result


def build_parser():
    p = argparse.ArgumentParser(
        description="Bounce switchports and verify MAC re-appearance"
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)
    p.add_argument(
        "-i", "--interfaces", nargs="+", required=True,
        metavar="INTF", help="Interface(s) to bounce"
    )
    p.add_argument(
        "--verify-mac", nargs="*", default=[],
        metavar="MAC", help="MAC address(es) expected to re-appear after bounce"
    )
    p.add_argument(
        "--wait", type=int, default=30,
        help="Seconds to hold interface down (default: 30)"
    )
    p.add_argument(
        "--mac-timeout", type=int, default=120,
        help="Seconds to wait for MAC re-appearance (default: 120)"
    )
    p.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type (default: cisco_ios)"
    )
    p.add_argument(
        "--port", type=int, default=22,
        help="SSH port (default: 22)"
    )
    p.add_argument("--secret", default="", help="Enable secret if required")
    p.add_argument("--debug", action="store_true")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

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

            all_results = []
            for intf in args.interfaces:
                res = process_interface(
                    conn, intf, args.verify_mac, args.wait, args.mac_timeout
                )
                all_results.append(res)

        print("\n--- Summary ---")
        exit_code = 0
        for r in all_results:
            status = "OK" if r["bounced"] else "FAILED"
            print(f"  {r['interface']}: bounce={status}")
            for mac, ok in r["mac_results"].items():
                if ok is None:
                    tag = "SKIP"
                elif ok:
                    tag = "SEEN"
                else:
                    tag = "MISSING"
                    exit_code = 1
                print(f"    MAC {mac}: {tag}")

        sys.exit(exit_code)

    except NetMikoAuthenticationException:
        log.error("Authentication failed for %s", args.device)
        sys.exit(2)
    except NetMikoTimeoutException:
        log.error("Connection timed out for %s", args.device)
        sys.exit(2)
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        sys.exit(2)
```