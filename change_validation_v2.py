route_verify.py - Post-change routing table verification

Purpose:
    Connects to a network device and verifies that expected routes exist in the
    routing table. Optionally validates next-hop IP and administrative distance.
    Designed for post-change validation after routing configuration changes.

Usage:
    python route_verify.py --host 10.0.0.1 --username admin --password secret \
        --routes 10.1.0.0/24 10.2.0.0/24 --nexthop 10.0.0.254

    python route_verify.py --host 10.0.0.1 --username admin --password secret \
        --routes 0.0.0.0/0 192.168.0.0/16 --max-ad 110 --device-type cisco_xe

Prerequisites:
    pip install netmiko
    Supported: cisco_ios, cisco_xe, cisco_nxos, cisco_xr
"""

import argparse
import logging
import re
import sys

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

ROUTE_COMMANDS = {
    "cisco_ios": "show ip route {prefix}",
    "cisco_xe": "show ip route {prefix}",
    "cisco_nxos": "show ip route {prefix}",
    "cisco_xr": "show route {prefix}",
}


def parse_route_output(output: str, prefix: str) -> dict:
    result = {
        "prefix": prefix,
        "found": False,
        "nexthops": [],
        "protocol": None,
        "ad": None,
        "metric": None,
    }

    if not output.strip() or output.strip().startswith("%"):
        return result
    if "not in table" in output.lower():
        return result

    result["found"] = True

    proto_match = re.search(
        r"^([A-Z*][A-Za-z0-9 ]*?)\s+\d+\.\d+\.\d+\.\d+", output, re.MULTILINE
    )
    if proto_match:
        result["protocol"] = proto_match.group(1).strip()

    ad_metric = re.search(r"\[(\d+)/(\d+)\]", output)
    if ad_metric:
        result["ad"] = int(ad_metric.group(1))
        result["metric"] = int(ad_metric.group(2))

    result["nexthops"] = re.findall(r"via (\d+\.\d+\.\d+\.\d+)", output)
    return result


def verify_routes(conn, prefixes, expected_nexthop=None, max_ad=None, device_type="cisco_ios"):
    cmd_tpl = ROUTE_COMMANDS.get(device_type, ROUTE_COMMANDS["cisco_ios"])
    results = {}

    for prefix in prefixes:
        cmd = cmd_tpl.format(prefix=prefix)
        logger.debug("Sending: %s", cmd)
        try:
            output = conn.send_command(cmd)
        except Exception as exc:
            logger.error("Command failed for %s: %s", prefix, exc)
            results[prefix] = {"error": str(exc), "passed": False}
            continue

        info = parse_route_output(output, prefix)
        info["passed"] = info["found"]

        if info["found"] and expected_nexthop and expected_nexthop not in info["nexthops"]:
            info["passed"] = False
            logger.warning(
                "%s found but nexthop %s not in %s",
                prefix, expected_nexthop, info["nexthops"],
            )

        if info["found"] and max_ad is not None and info["ad"] is not None:
            if info["ad"] > max_ad:
                info["passed"] = False
                logger.warning(
                    "%s AD %d exceeds max allowed %d", prefix, info["ad"], max_ad
                )

        results[prefix] = info

    return results


def print_results(results, hostname):
    passed = sum(1 for r in results.values() if r.get("passed"))
    failed = len(results) - passed

    print(f"\nRoute Verification Results — {hostname}")
    print("=" * 65)
    print(f"{'Prefix':<24} {'Status':<8} {'Proto':<10} {'AD/Metric':<12} Next-Hop(s)")
    print("-" * 65)

    for prefix, info in sorted(results.items()):
        if info.get("error"):
            print(f"{prefix:<24} {'ERROR':<8} -          -            {info['error'][:20]}")
            continue

        status = "PASS" if info["passed"] else "FAIL"
        proto = info.get("protocol") or ("-" if not info["found"] else "?")
        if info["ad"] is not None:
            ad_metric = f"{info['ad']}/{info['metric']}"
        else:
            ad_metric = "-"
        if info["nexthops"]:
            nexthops = ", ".join(info["nexthops"])
        elif info["found"]:
            nexthops = "connected"
        else:
            nexthops = "missing"
        print(f"{prefix:<24} {status:<8} {proto:<10} {ad_metric:<12} {nexthops}")

    print("-" * 65)
    print(f"Total: {len(results)}  Passed: {passed}  Failed: {failed}\n")
    return 0 if failed == 0 else 1


def build_parser():
    p = argparse.ArgumentParser(
        description="Verify expected routes exist on a network device."
    )
    p.add_argument("--host", required=True, help="Device IP or hostname")
    p.add_argument("--username", required=True, help="SSH username")
    p.add_argument("--password", required=True, help="SSH password")
    p.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=list(ROUTE_COMMANDS.keys()),
        help="Netmiko device type (default: cisco_ios)",
    )
    p.add_argument(
        "--routes",
        nargs="+",
        required=True,
        metavar="PREFIX",
        help="Prefixes to verify, e.g. 10.0.0.0/8 192.168.1.0/24",
    )
    p.add_argument("--nexthop", metavar="IP", help="Required next-hop IP address")
    p.add_argument(
        "--max-ad", type=int, metavar="N", help="Fail routes with AD above this value"
    )
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--timeout", type=int, default=30, help="Connection timeout seconds")
    p.add_argument("--verbose", action="store_true", help="Debug logging")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    device_params = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "timeout": args.timeout,
    }

    logger.info("Connecting to %s (%s)", args.host, args.device_type)
    try:
        with ConnectHandler(**device_params) as conn:
            hostname = conn.find_prompt().rstrip("#> ")
            logger.info("Connected — %s", hostname)
            results = verify_routes(
                conn,
                args.routes,
                expected_nexthop=args.nexthop,
                max_ad=args.max_ad,
                device_type=args.device_type,
            )
    except NetmikoAuthenticationException:
        logger.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(2)
    except NetmikoTimeoutException:
        logger.error("Connection timed out to %s", args.host)
        sys.exit(2)
    except Exception as exc:
        logger.error("Unexpected error: %s", exc)
        sys.exit(2)

    sys.exit(print_results(results, hostname))