Here's the script:

```python
"""
PoE Port Recycler — power-cycle PoE-powered devices via Cisco IOS/IOS-XE.

Unlike a generic port bounce, this script targets Power over Ethernet ports
specifically: it captures pre-cycle PoE status and power draw, issues
`power inline reset` (or shutdown/no shutdown on unsupported platforms),
then polls until the powered device re-negotiates and reports its wattage.

Usage:
    python poe_port_recycler.py -d 192.168.1.1 -u admin -p secret \
        -i GigabitEthernet1/0/5 GigabitEthernet1/0/12

    python poe_port_recycler.py -d 192.168.1.1 -u admin -p secret \
        -i GigabitEthernet1/0/5 --timeout 60 --device-type cisco_ios

Prerequisites:
    pip install netmiko
"""

import argparse
import logging
import re
import sys
import time

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger(__name__)

POE_STATUS_RE = re.compile(
    r"^(?P<iface>\S+)\s+(?P<admin>\S+)\s+(?P<oper>\S+)\s+(?P<power>[\d.]+)\s+(?P<device>\S+)\s+(?P<class>\S+)",
    re.MULTILINE,
)


def parse_poe_status(output: str, iface: str) -> dict | None:
    """Extract PoE fields for a specific interface from `show power inline` output."""
    short = iface.replace("GigabitEthernet", "Gi").replace("FastEthernet", "Fa")
    for m in POE_STATUS_RE.finditer(output):
        if m.group("iface").startswith(short) or m.group("iface").startswith(iface):
            return m.groupdict()
    return None


def get_poe_status(conn, iface: str) -> dict | None:
    out = conn.send_command(f"show power inline {iface}")
    return parse_poe_status(out, iface)


def recycle_port(conn, iface: str, use_inline_reset: bool, wait: int) -> bool:
    """Power-cycle a single PoE port. Returns True if the port came back powered."""
    if use_inline_reset:
        log.info("[%s] Issuing 'power inline reset'", iface)
        conn.send_config_set([f"interface {iface}", "power inline reset"])
    else:
        log.info("[%s] Bouncing via shutdown / no shutdown", iface)
        conn.send_config_set([f"interface {iface}", "shutdown"])
        time.sleep(2)
        conn.send_config_set([f"interface {iface}", "no shutdown"])

    log.info("[%s] Waiting up to %ds for device to re-negotiate PoE", iface, wait)
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        time.sleep(5)
        status = get_poe_status(conn, iface)
        if status and status["oper"].lower() in ("on", "powered"):
            log.info(
                "[%s] Device re-powered. Draw: %sW  Class: %s",
                iface,
                status["power"],
                status["class"],
            )
            return True
        oper = status["oper"] if status else "unknown"
        log.debug("[%s] PoE state: %s — still waiting…", iface, oper)

    log.warning("[%s] Device did not re-power within %ds", iface, wait)
    return False


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Recycle PoE ports and verify device recovery.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-d", "--device", required=True, help="Device IP or hostname")
    p.add_argument("-u", "--username", required=True, help="SSH username")
    p.add_argument("-p", "--password", required=True, help="SSH password")
    p.add_argument(
        "-i", "--interfaces", required=True, nargs="+",
        help="One or more interface names (e.g. GigabitEthernet1/0/5)"
    )
    p.add_argument(
        "--device-type", default="cisco_ios",
        help="Netmiko device type"
    )
    p.add_argument(
        "--timeout", type=int, default=45,
        help="Seconds to wait per port for PoE re-negotiation"
    )
    p.add_argument(
        "--no-inline-reset", action="store_true",
        help="Use shutdown/no-shutdown instead of 'power inline reset'"
    )
    p.add_argument(
        "--secret", default="",
        help="Enable secret (if required)"
    )
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


def main() -> int:
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    device_params = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "secret": args.secret,
        "timeout": 30,
    }

    try:
        log.info("Connecting to %s", args.device)
        with ConnectHandler(**device_params) as conn:
            if args.secret:
                conn.enable()

            results = {}
            for iface in args.interfaces:
                pre = get_poe_status(conn, iface)
                if pre is None:
                    log.error("[%s] Not found in PoE table — skipping", iface)
                    results[iface] = "skipped"
                    continue

                log.info(
                    "[%s] Pre-cycle: oper=%s power=%sW class=%s device=%s",
                    iface, pre["oper"], pre["power"], pre["class"], pre["device"],
                )

                if pre["oper"].lower() not in ("on", "powered"):
                    log.warning(
                        "[%s] Port is not currently powered (oper=%s) — recycling anyway",
                        iface, pre["oper"],
                    )

                ok = recycle_port(
                    conn, iface,
                    use_inline_reset=not args.no_inline_reset,
                    wait=args.timeout,
                )
                results[iface] = "recovered" if ok else "failed"

        log.info("--- Summary ---")
        failures = 0
        for iface, outcome in results.items():
            log.info("  %-35s %s", iface, outcome.upper())
            if outcome == "failed":
                failures += 1

        return 0 if failures == 0 else 1

    except NetmikoAuthenticationException:
        log.error("Authentication failed for %s", args.device)
        return 2
    except NetmikoTimeoutException:
        log.error("Connection timed out to %s", args.device)
        return 2
    except Exception as exc:
        log.error("Unexpected error: %s", exc)
        return 3


if __name__ == "__main__":
    sys.exit(main())
```

This is `poe_port_recycler.py` — differentiated from the existing port-bounce scripts by targeting PoE specifically: it parses `show power inline` before and after the cycle, prefers `power inline reset` over shutdown/no-shutdown (Cisco's purpose-built command for this), and polls until the powered device re-negotiates rather than just waiting a fixed delay. Exit code reflects per-port success so it's scriptable in CI/NOC pipelines.