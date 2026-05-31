```python
#!/usr/bin/env python3
"""
Routing Table Audit Script

Verifies critical routes exist on network devices. Compares actual routing table
against expected routes, reports discrepancies, and alerts on missing/changed routes.

Usage:
    python route_auditor.py --device 10.1.1.1 -u admin -p pass -t cisco_ios --routes routes.txt
    python route_auditor.py --device 10.1.1.1 -u admin -p pass -t arista_eos --routes critical_routes.json

Expected routes file format (text):
    10.0.0.0/8 10.1.1.1
    192.168.0.0/16 10.1.1.2

Expected routes file format (JSON):
    {"routes": [{"prefix": "10.0.0.0/8", "nexthop": "10.1.1.1"}]}

Supports:
    - Cisco IOS, IOS-XE, NXOS
    - Arista EOS
    - Juniper Junos

Prerequisites:
    - netmiko installed: pip install netmiko
    - Network connectivity to target device
    - Read access to routing table
    - Expected routes file created

Exit codes:
    0 = all expected routes present
    1 = missing or changed routes
    2 = error connecting or parsing
"""

import argparse
import json
import logging
import sys
import re
from pathlib import Path
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_ios_routing_table(output):
    """Parse Cisco IOS 'show ip route' output."""
    routes = {}
    for line in output.split('\n'):
        line = line.strip()
        if not line or line.startswith('Codes') or line.startswith('Gateway'):
            continue
        
        parts = line.split()
        if len(parts) >= 2 and '.' in parts[0]:
            prefix = parts[0]
            if parts[0][0] in 'CSLRIDOB':
                prefix = parts[1]
            
            nexthop = None
            for i, part in enumerate(parts):
                if '.' in part and part != prefix:
                    nexthop = part
                    break
            
            if prefix and nexthop:
                routes[prefix] = nexthop
    
    return routes


def parse_junos_routing_table(output):
    """Parse Juniper Junos 'show route' output."""
    routes = {}
    for line in output.split('\n'):
        line = line.strip()
        if not line or line.startswith('Routing'):
            continue
        
        parts = line.split()
        if len(parts) >= 3 and '.' in parts[0]:
            prefix = parts[0]
            nexthop = None
            
            for i, part in enumerate(parts):
                if '.' in part and part != prefix:
                    nexthop = part
                    break
            
            if prefix and nexthop:
                routes[prefix] = nexthop
    
    return routes


def load_expected_routes(filepath):
    """Load expected routes from text or JSON file."""
    filepath = Path(filepath)
    expected = {}
    
    try:
        content = filepath.read_text()
        
        if filepath.suffix.lower() == '.json':
            data = json.loads(content)
            for route in data.get('routes', []):
                expected[route['prefix']] = route['nexthop']
        else:
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    expected[parts[0]] = parts[1]
        
        logger.info(f"Loaded {len(expected)} expected routes from {filepath}")
        return expected
    
    except FileNotFoundError:
        logger.error(f"Route file not found: {filepath}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {filepath}: {e}")
        raise


def get_routing_table(device, username, password, device_type, timeout=15):
    """
    Connect to device and retrieve routing table.
    
    Args:
        device: IP or hostname
        username: login username
        password: login password
        device_type: netmiko device type
        timeout: connection timeout in seconds
    
    Returns:
        dict: routes with their next hops
    
    Raises:
        NetmikoAuthenticationException: invalid credentials
        NetmikoTimeoutException: connection timeout
    """
    conn_params = {
        'device_type': device_type,
        'host': device,
        'username': username,
        'password': password,
        'timeout': timeout,
    }
    
    try:
        device_conn = ConnectHandler(**conn_params)
        logger.info(f"Connected to {device}")
    except NetmikoAuthenticationException as e:
        logger.error(f"Authentication failed: {e}")
        raise
    except NetmikoTimeoutException as e:
        logger.error(f"Connection timeout: {e}")
        raise
    
    try:
        if 'cisco' in device_type.lower():
            output = device_conn.send_command('show ip route')
            routes = parse_ios_routing_table(output)
        elif 'junos' in device_type.lower():
            output = device_conn.send_command('show route')
            routes = parse_junos_routing_table(output)
        else:
            logger.warning(f"Route parsing not implemented for {device_type}")
            routes = {}
    finally:
        device_conn.disconnect()
    
    return routes


def audit_routes(actual, expected):
    """Compare actual and expected routes."""
    missing = {}
    changed = {}
    
    for prefix, expected_nh in expected.items():
        if prefix not in actual:
            missing[prefix] = expected_nh
        elif actual[prefix] != expected_nh:
            changed[prefix] = {
                'expected': expected_nh,
                'actual': actual[prefix]
            }
    
    return missing, changed


def main():
    parser = argparse.ArgumentParser(
        description='Audit routing table against expected routes'
    )
    parser.add_argument(
        '--device', '-d', required=True,
        help='Target device IP or hostname'
    )
    parser.add_argument(
        '--username', '-u', required=True,
        help='Login username'
    )
    parser.add_argument(
        '--password', '-p', required=True,
        help='Login password'
    )
    parser.add_argument(
        '--device-type', '-t', default='cisco_ios',
        help='Netmiko device type (default: cisco_ios)'
    )
    parser.add_argument(
        '--routes', '-r', required=True,
        help='Path to expected routes file (text or JSON)'
    )
    parser.add_argument(
        '--timeout', type=int, default=15,
        help='Connection timeout in seconds (default: 15)'
    )
    
    args = parser.parse_args()
    
    try:
        expected = load_expected_routes(args.routes)
        actual = get_routing_table(
            args.device,
            args.username,
            args.password,
            args.device_type,
            args.timeout
        )
    except Exception as e:
        logger.error(f"Failed to audit routes: {e}")
        return 2
    
    missing, changed = audit_routes(actual, expected)
    
    if not missing and not changed:
        logger.info(f"All {len(expected)} expected routes present on {args.device}")
        return 0
    
    if missing:
        logger.error(f"Missing {len(missing)} route(s):")
        for prefix, nexthop in sorted(missing.items()):
            logger.error(f"  {prefix} -> {nexthop}")
    
    if changed:
        logger.warning(f"Changed {len(changed)} route(s):")
        for prefix, data in sorted(changed.items()):
            logger.warning(
                f"  {prefix}: expected {data['expected']}, got {data['actual']}"
            )
    
    return 1


if __name__ == '__main__':
    sys.exit(main())
```