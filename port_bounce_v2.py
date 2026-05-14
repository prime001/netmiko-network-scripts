port_bounce_v3.py - Interface bounce with pre/post state verification and reporting.

Captures interface counters, line-protocol state, and MAC address table entries
before and after the bounce, then writes a structured JSON report. Useful for
proving that an interface recovered cleanly and that end-devices re-learned.

Usage:
    python port_bounce_v3.py -H 10.0.0.1 -u admin -p secret \
        -i GigabitEthernet0/1 --wait 10 --output report.json

    python port_bounce_v3.py -H 10.0.0.1 -u admin -p secret \
        -i Gi0/1,Gi0/2,Gi0/3 --link-timeout 90 --no-verify

Prerequisites:
    pip install netmiko
    SSH access with privilege level sufficient for 'show interface',
    'show mac address-table', and interface configuration commands.
    Supported device types: cisco_ios, cisco_xe, cisco_nxos, arista_eos
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

SUPPORTED_TYPES = ["cisco_ios", "cisco_xe", "cisco_nxos", "arista_eos"]


def capture_state(conn, interface: str, device_type: str) -> dict:
    state = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "interface": interface,
        "line_protocol": "unknown",
        "input_errors": None,
        "output_errors": None,
        "mac_count": None,
    }

    intf_output = conn.send_command(f"show interface {interface}", use_textfsm=False)
    for line in intf_output.splitlines():
        stripped = line.strip().lower()
        if "line protocol" in stripped:
            state["line_protocol"] = "up" if "line protocol is up" in stripped else "down"
        if "input errors" in stripped:
            state["input_errors"] = line.strip()
        if "output errors" in stripped:
            state["output_errors"] = line.strip()

    try:
        if "nxos" in device_type:
            mac_cmd = f"show mac address-table interface {interface}"
        else:
            mac_cmd = f"show mac address-table interface {interface}"
        mac_output = conn.send_command(mac_cmd, use_textfsm=False)
        state["mac_count"] = sum(
            1 for ln in mac_output.splitlines()
            if ln.strip()
            and not ln.strip().startswith(("Mac", "Vlan", "-", "Legend", "Total"))
            and len(ln.split()) >= 4
        )
    except Exception as exc:
        log.debug("MAC table capture skipped for %s: %s", interface, exc)

    return state


def bounce(conn, interface: str, device_type: str, wait_seconds: int) -> None:
    log.info("Shutting down %s", interface)
    if "nxos" in device_type:
        conn.send_config_set([f"interface {interface}", "shutdown"])
        time.sleep(wait_seconds)
        conn.send_config_set([f"interface {interface}", "no shutdown"])
    else:
        conn.send_config_set([f"interface {interface}", "shutdown"])
        time.sleep(wait_seconds)
        conn.send_config_set([f"interface {interface}", "no shutdown"])
    log.info("Re-enabled %s", interface)


def wait_for_up(conn, interface: str, timeout: int, poll_interval: int = 5) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        out = conn.send_command(f"show interface {interface}", use_textfsm=False)
        if "line protocol is up" in out.lower():
            log.info("%s is up", interface)
            return True
        remaining = int(deadline - time.monotonic())
        log.debug("%s still down, %ds remaining", interface, remaining)
        time.sleep(poll_interval)
    log.warning("%s did not come up within %ds", interface, timeout)
    return False


def build_report(interface: str, pre: dict, post: dict, recovered: bool) -> dict:
    pre_mac = pre.get("mac_count")
    post_mac = post.get("mac_count")
    return {
        "interface": interface,
        "bounce_at": pre.get("timestamp"),
        "recovered": recovered,
        "pre": pre,
        "post": post,
        "mac_delta": (post_mac - pre_mac) if (pre_mac is not None and post_mac is not None) else None,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bounce one or more interfaces and verify recovery."
    )
    parser.add_argument("-H", "--host", required=True, help="Device IP or hostname")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument(
        "-i", "--interfaces", required=True,
        help="Comma-separated interface list, e.g. GigabitEthernet0/1,Gi0/2"
    )
    parser.add_argument(
        "-t", "--device-type", default="cisco_ios", choices=SUPPORTED_TYPES
    )
    parser.add_argument(
        "--port", type=int, default=22, help="SSH port (default: 22)"
    )
    parser.add_argument(
        "--wait", type=int, default=5,
        help="Seconds to hold interface down (default: 5)"
    )
    parser.add_argument(
        "--link-timeout", type=int, default=60,
        help="Seconds to wait for link-up after no-shut (default: 60)"
    )
    parser.add_argument(
        "--no-verify", action="store_true",
        help="Skip pre/post capture and link-up polling"
    )
    parser.add_argument(
        "--output", metavar="FILE",
        help="Write JSON report to FILE instead of stdout"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    interfaces = [i.strip() for i in args.interfaces.split(",") if i.strip()]
    if not interfaces:
        log.error("No interfaces provided.")
        return 1

    device_params = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
    }

    reports = []
    try:
        log.info("Connecting to %s (%s)", args.host, args.device_type)
        with ConnectHandler(**device_params) as conn:
            for iface in interfaces:
                log.info("Processing %s", iface)
                pre = capture_state(conn, iface, args.device_type) if not args.no_verify else {}
                bounce(conn, iface, args.device_type, args.wait)
                recovered = True
                if not args.no_verify:
                    recovered = wait_for_up(conn, iface, timeout=args.link_timeout)
                post = capture_state(conn, iface, args.device_type) if not args.no_verify else {}
                reports.append(build_report(iface, pre, post, recovered))
                if not recovered:
                    log.error("%s did not recover — manual investigation required", iface)
    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s@%s", args.username, args.host)
        return 2
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.host)
        return 3
    except Exception as exc:
        log.error("Unexpected error: %s", exc, exc_info=args.verbose)
        return 4

    payload = json.dumps(reports, indent=2)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(payload)
        log.info("Report written to %s", args.output)
    else:
        print(payload)

    failed = sum(1 for r in reports if not r.get("recovered", True))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())