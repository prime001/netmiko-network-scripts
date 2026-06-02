This is the NetAutoCommitter project, not the portfolio repo — the existing scripts list is from the prompt context. Here's the script:

```python
"""
bgp_session_monitor.py - BGP Neighbor Session Monitor

Purpose:
    Connects to a router and audits BGP neighbor sessions. Reports each
    neighbor's state, remote AS, uptime, and received prefix count. Alerts
    on any neighbor not in Established state and optionally validates that
    the expected number of neighbors is present.

    Exit codes: 0 = all sessions healthy, 1 = alerts raised, 2 = connection error.
    The non-zero exit on alerts makes this suitable for Nagios/monitoring integrations.

Usage:
    python bgp_session_monitor.py -H 10.0.0.1 -u admin -p secret
    python bgp_session_monitor.py -H 10.0.0.1 -u admin --key-file ~/.ssh/id_rsa \
        --device-type cisco_xr --expected 4
    python bgp_session_monitor.py -H 10.0.0.1 -u admin -p secret \
        --output json --log-level DEBUG

Prerequisites:
    pip install netmiko
    Python 3.9+
    Supported device types: cisco_ios, cisco_ios_xe, cisco_xr, juniper_junos
"""

import argparse
import json
import logging
import re
import sys
from dataclasses import asdict, dataclass
from getpass import getpass
from typing import Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


@dataclass
class BgpNeighbor:
    neighbor: str
    remote_as: str
    state: str
    uptime: str
    prefixes_received: Optional[int]
    established: bool


def _parse_ios_summary(output: str) -> list[BgpNeighbor]:
    neighbors = []
    # Matches neighbor rows: IP  ver  AS  MsgRcvd MsgSent TblVer InQ OutQ Up/Down State|PfxRcd
    pattern = re.compile(
        r'^(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)\s+'
        r'\d+\s+(\d+)\s+'
        r'\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+'
        r'(\S+)\s+(\S+)\s*$',
        re.MULTILINE,
    )
    for m in pattern.finditer(output):
        peer, remote_as, uptime, state_field = m.groups()
        try:
            pfx_count = int(state_field)
            established, state = True, 'Established'
        except ValueError:
            pfx_count = None
            established, state = False, state_field
        neighbors.append(BgpNeighbor(
            neighbor=peer,
            remote_as=remote_as,
            state=state,
            uptime=uptime,
            prefixes_received=pfx_count,
            established=established,
        ))
    return neighbors


def _parse_junos_summary(output: str) -> list[BgpNeighbor]:
    neighbors = []
    # Junos: Peer  AS  InPkt OutPkt OutQ Flaps Up/Dwn State|Active/Received/Accepted/Damped
    pattern = re.compile(
        r'^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+'
        r'\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)',
        re.MULTILINE,
    )
    for m in pattern.finditer(output):
        peer, remote_as, uptime, state_field = m.groups()
        if '/' in state_field:
            parts = state_field.split('/')
            try:
                pfx_count = int(parts[1])
                established, state = True, 'Established'
            except (ValueError, IndexError):
                pfx_count = None
                established, state = False, state_field
        else:
            pfx_count = None
            established = state_field.lower() == 'established'
            state = state_field
        neighbors.append(BgpNeighbor(
            neighbor=peer,
            remote_as=remote_as,
            state=state,
            uptime=uptime,
            prefixes_received=pfx_count,
            established=established,
        ))
    return neighbors


_BGP_COMMANDS = {
    'cisco_ios': 'show ip bgp summary',
    'cisco_ios_xe': 'show ip bgp summary',
    'cisco_xr': 'show bgp summary',
    'juniper_junos': 'show bgp summary',
}

_PARSERS = {
    'cisco_ios': _parse_ios_summary,
    'cisco_ios_xe': _parse_ios_summary,
    'cisco_xr': _parse_ios_summary,
    'juniper_junos': _parse_junos_summary,
}


def check_bgp_sessions(
    host: str,
    username: str,
    password: str,
    device_type: str,
    port: int = 22,
    expected_count: Optional[int] = None,
    key_file: Optional[str] = None,
) -> tuple[list[BgpNeighbor], list[str]]:
    device_params = {
        'device_type': device_type,
        'host': host,
        'username': username,
        'password': password,
        'port': port,
    }
    if key_file:
        device_params.update({'use_keys': True, 'key_file': key_file})

    logging.info("Connecting to %s (%s)", host, device_type)
    with ConnectHandler(**device_params) as conn:
        command = _BGP_COMMANDS[device_type]
        logging.debug("Sending: %s", command)
        output = conn.send_command(command)

    neighbors = _PARSERS[device_type](output)
    alerts: list[str] = []

    if not neighbors:
        alerts.append(f"No BGP neighbors parsed from output — verify device type and BGP config")
        return neighbors, alerts

    for n in neighbors:
        if not n.established:
            alerts.append(
                f"Neighbor {n.neighbor} (AS {n.remote_as}) is {n.state}, not Established"
            )

    if expected_count is not None and len(neighbors) != expected_count:
        alerts.append(
            f"Expected {expected_count} neighbor(s), found {len(neighbors)}"
        )

    return neighbors, alerts


def _print_table(neighbors: list[BgpNeighbor], alerts: list[str], host: str) -> None:
    print(f"\nBGP Session Report — {host}")
    print(f"{'Neighbor':<22} {'Remote AS':<12} {'State':<14} {'Uptime':<14} Pfx Rcvd")
    print('─' * 74)
    for n in neighbors:
        pfx = str(n.prefixes_received) if n.prefixes_received is not None else '—'
        print(f"{n.neighbor:<22} {n.remote_as:<12} {n.state:<14} {n.uptime:<14} {pfx}")
    print()
    if alerts:
        print("ALERTS:")
        for a in alerts:
            print(f"  [!] {a}")
    else:
        print("  All BGP sessions are Established.")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Audit BGP neighbor sessions on a router',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('-H', '--host', required=True, help='Device hostname or IP')
    parser.add_argument('-u', '--username', required=True, help='SSH username')
    parser.add_argument('-p', '--password', help='SSH password (prompted if omitted)')
    parser.add_argument('--key-file', help='Path to SSH private key')
    parser.add_argument(
        '--device-type', default='cisco_ios',
        choices=list(_BGP_COMMANDS.keys()),
        help='Netmiko device type',
    )
    parser.add_argument('--port', type=int, default=22, help='SSH port')
    parser.add_argument(
        '--expected', type=int, metavar='N',
        help='Alert if neighbor count does not equal N',
    )
    parser.add_argument(
        '--output', choices=['table', 'json'], default='table',
        help='Output format',
    )
    parser.add_argument(
        '--log-level', default='WARNING',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Logging verbosity',
    )
    args = parser.parse_args()

    logging.basicConfig(
        format='%(asctime)s %(levelname)s %(message)s',
        level=getattr(logging, args.log_level),
    )

    password = args.password or getpass(f'Password for {args.username}@{args.host}: ')

    try:
        neighbors, alerts = check_bgp_sessions(
            host=args.host,
            username=args.username,
            password=password,
            device_type=args.device_type,
            port=args.port,
            expected_count=args.expected,
            key_file=args.key_file,
        )
    except NetmikoAuthenticationException:
        logging.error("Authentication failed for %s@%s", args.username, args.host)
        sys.exit(2)
    except NetmikoTimeoutException:
        logging.error("Connection timed out: %s", args.host)
        sys.exit(2)
    except Exception as exc:
        logging.error("Unexpected error: %s", exc)
        sys.exit(2)

    if args.output == 'json':
        result = {
            'host': args.host,
            'neighbors': [asdict(n) for n in neighbors],
            'alerts': alerts,
            'ok': not alerts,
        }
        print(json.dumps(result, indent=2))
    else:
        _print_table(neighbors, alerts, args.host)

    sys.exit(1 if alerts else 0)


if __name__ == '__main__':
    main()
```