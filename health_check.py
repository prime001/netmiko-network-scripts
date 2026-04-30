```python
"""
007_device_health_check.py — Network Device Health Check

Connects to one or more network devices and collects key health metrics:
CPU utilization, memory usage, interface error counters, and environment
status (temperature/power/fans where supported). Outputs a pass/warn/fail
summary per device and exits non-zero if any device fails threshold checks.

Usage:
    Single device:
        python 007_device_health_check.py -H 192.168.1.1 -u admin -p secret

    Device list file (one host per line):
        python 007_device_health_check.py -f hosts.txt -u admin -p secret

    Adjust thresholds:
        python 007_device_health_check.py -H 192.168.1.1 -u admin -p secret \
            --cpu-warn 70 --cpu-crit 90 --mem-warn 80 --mem-crit 95

Prerequisites:
    pip install netmiko
    Device types supported: cisco_ios, cisco_nxos, cisco_xr, arista_eos
"""

import argparse
import logging
import sys
from dataclasses import dataclass, field
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import AuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

STATUS_OK = "OK"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"


@dataclass
class HealthResult:
    host: str
    device_type: str
    reachable: bool = False
    cpu_pct: Optional[float] = None
    mem_pct: Optional[float] = None
    interface_errors: int = 0
    env_ok: Optional[bool] = None
    status: str = STATUS_FAIL
    notes: list = field(default_factory=list)


def parse_cpu_ios(output: str) -> Optional[float]:
    for line in output.splitlines():
        if "CPU utilization" in line:
            for token in line.split():
                if token.endswith("%"):
                    try:
                        return float(token.rstrip("%"))
                    except ValueError:
                        pass
    return None


def parse_mem_ios(output: str) -> Optional[float]:
    for line in output.splitlines():
        if "Processor" in line and "K" in line:
            parts = line.split()
            try:
                used = int(parts[2])
                free = int(parts[4])
                total = used + free
                if total:
                    return round(used / total * 100, 1)
            except (IndexError, ValueError):
                pass
    return None


def count_interface_errors_ios(output: str) -> int:
    total = 0
    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            try:
                count = int(parts[0].replace(",", ""))
                label = " ".join(parts[1:]).lower()
                if any(k in label for k in ("input error", "output error", "crc", "reset")):
                    total += count
            except ValueError:
                pass
    return total


def check_env_ios(output: str) -> bool:
    critical_keywords = ("CRITICAL", "FAULTY", "shutdown", "NOT OK")
    for line in output.splitlines():
        if any(k in line for k in critical_keywords):
            return False
    return True


def run_health_check(
    host: str,
    username: str,
    password: str,
    device_type: str,
    cpu_warn: int,
    cpu_crit: int,
    mem_warn: int,
    mem_crit: int,
    port: int = 22,
    timeout: int = 30,
) -> HealthResult:
    result = HealthResult(host=host, device_type=device_type)

    try:
        conn = ConnectHandler(
            device_type=device_type,
            host=host,
            username=username,
            password=password,
            port=port,
            timeout=timeout,
            session_log=None,
        )
        result.reachable = True
    except AuthenticationException:
        result.notes.append("Authentication failed")
        log.warning("%s: authentication failed", host)
        return result
    except NetmikoTimeoutException:
        result.notes.append("Connection timed out")
        log.warning("%s: connection timed out", host)
        return result
    except Exception as exc:
        result.notes.append(f"Connection error: {exc}")
        log.warning("%s: %s", host, exc)
        return result

    try:
        cpu_out = conn.send_command("show processes cpu | include CPU utilization")
        result.cpu_pct = parse_cpu_ios(cpu_out)

        mem_out = conn.send_command("show processes memory | include Processor")
        result.mem_pct = parse_mem_ios(mem_out)

        err_out = conn.send_command("show interfaces counters errors", use_textfsm=False)
        result.interface_errors = count_interface_errors_ios(err_out)

        env_out = conn.send_command("show environment all")
        result.env_ok = check_env_ios(env_out)
    except Exception as exc:
        result.notes.append(f"Command error: {exc}")
        log.warning("%s: command error — %s", host, exc)
    finally:
        conn.disconnect()

    worst = STATUS_OK
    if result.cpu_pct is not None:
        if result.cpu_pct >= cpu_crit:
            worst = STATUS_FAIL
            result.notes.append(f"CPU critical: {result.cpu_pct}%")
        elif result.cpu_pct >= cpu_warn:
            if worst != STATUS_FAIL:
                worst = STATUS_WARN
            result.notes.append(f"CPU high: {result.cpu_pct}%")

    if result.mem_pct is not None:
        if result.mem_pct >= mem_crit:
            worst = STATUS_FAIL
            result.notes.append(f"Memory critical: {result.mem_pct}%")
        elif result.mem_pct >= mem_warn:
            if worst != STATUS_FAIL:
                worst = STATUS_WARN
            result.notes.append(f"Memory high: {result.mem_pct}%")

    if result.env_ok is False:
        worst = STATUS_FAIL
        result.notes.append("Environment alarm detected")

    if result.interface_errors > 0:
        result.notes.append(f"Interface errors: {result.interface_errors}")
        if worst == STATUS_OK:
            worst = STATUS_WARN

    result.status = worst
    return result


def format_result(r: HealthResult) -> str:
    cpu = f"{r.cpu_pct}%" if r.cpu_pct is not None else "n/a"
    mem = f"{r.mem_pct}%" if r.mem_pct is not None else "n/a"
    env = "ok" if r.env_ok else ("alarm" if r.env_ok is False else "n/a")
    notes = "; ".join(r.notes) if r.notes else "—"
    return (
        f"[{r.status:<4}] {r.host:<20} "
        f"cpu={cpu:<6} mem={mem:<6} iferr={r.interface_errors:<5} env={env:<6} | {notes}"
    )


def main():
    parser = argparse.ArgumentParser(
        description="Network device health check via netmiko"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-H", "--host", help="Single device hostname or IP")
    group.add_argument("-f", "--file", help="File with one host per line")
    parser.add_argument("-u", "--username", required=True)
    parser.add_argument("-p", "--password", required=True)
    parser.add_argument("-t", "--device-type", default="cisco_ios",
                        choices=["cisco_ios", "cisco_nxos", "cisco_xr", "arista_eos"])
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--cpu-warn", type=int, default=75, metavar="PCT")
    parser.add_argument("--cpu-crit", type=int, default=90, metavar="PCT")
    parser.add_argument("--mem-warn", type=int, default=80, metavar="PCT")
    parser.add_argument("--mem-crit", type=int, default=95, metavar="PCT")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    hosts = []
    if args.host:
        hosts = [args.host]
    else:
        try:
            with open(args.file) as fh:
                hosts = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except OSError as exc:
            print(f"Cannot read host file: {exc}", file=sys.stderr)
            sys.exit(2)

    results = []
    for host in hosts:
        log.info("Checking %s", host)
        r = run_health_check(
            host=host,
            username=args.username,
            password=args.password,
            device_type=args.device_type,
            cpu_warn=args.cpu_warn,
            cpu_crit=args.cpu_crit,
            mem_warn=args.mem_warn,
            mem_crit=args.mem_crit,
            port=args.port,
            timeout=args.timeout,
        )
        results.append(r)
        print(format_result(r))

    totals = {STATUS_OK: 0, STATUS_WARN: 0, STATUS_FAIL: 0}
    for r in results:
        totals[r.status] = totals.get(r.status, 0) + 1

    print(
        f"\nSummary: {len(results)} device(s) — "
        f"OK={totals[STATUS_OK]} WARN={totals[STATUS_WARN]} FAIL={totals[STATUS_FAIL]}"
    )

    if totals[STATUS_FAIL] > 0:
        sys.exit(2)
    if totals[STATUS_WARN] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
```