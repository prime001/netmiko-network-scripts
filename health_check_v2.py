```python
#!/usr/bin/env python
"""
NTP Synchronization Validator

Validates NTP synchronization status on network devices and reports clock accuracy.
Supports Cisco IOS, IOS-XE, NXOS platforms.

Usage:
    python ntp_sync_validator.py --device 192.168.1.1 --username admin --password pass
    python ntp_sync_validator.py --device 192.168.1.1 -u admin -p pass --device-type cisco_ios

Prerequisites:
    - netmiko library: pip install netmiko
    - Network device with SSH enabled
    - Read-only access credentials
"""

import argparse
import logging
import sys
from datetime import datetime
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def parse_ntp_status(output, device_type):
    """Extract NTP metrics from device output."""
    metrics = {'synchronized': False, 'stratum': None, 'offset_ms': None, 'peers': 0}
    
    if device_type in ['cisco_ios', 'cisco_xe']:
        metrics['synchronized'] = 'synchronized' in output.lower()
        for line in output.split('\n'):
            if 'Stratum' in line:
                try:
                    metrics['stratum'] = int(line.split()[-1])
                except (IndexError, ValueError):
                    pass
            elif 'offset is' in line.lower():
                try:
                    metrics['offset_ms'] = float(line.split()[-2])
                except (IndexError, ValueError):
                    pass
        metrics['peers'] = output.count('*') + output.count('+') + output.count('o')
    elif device_type == 'cisco_nxos':
        metrics['synchronized'] = 'synchronized' in output.lower()
        for line in output.split('\n'):
            if 'stratum' in line.lower():
                try:
                    metrics['stratum'] = int(line.split()[-1])
                except (IndexError, ValueError):
                    pass
    
    return metrics


def validate_ntp(device, device_type, username, password, max_offset, port):
    """Connect to device and validate NTP synchronization."""
    try:
        logger.info(f"Connecting to {device}")
        conn = ConnectHandler(
            device_type=device_type,
            host=device,
            username=username,
            password=password,
            port=port,
            timeout=10,
            global_delay_factor=1
        )
        
        if device_type in ['cisco_ios', 'cisco_xe']:
            output = conn.send_command('show ntp status')
            output += '\n' + conn.send_command('show ntp associations')
        elif device_type == 'cisco_nxos':
            output = conn.send_command('show ntp peer-status')
        else:
            output = conn.send_command('show ntp status')
        
        conn.disconnect()
        logger.info(f"Disconnected from {device}")
        
        metrics = parse_ntp_status(output, device_type)
        
        issues = []
        if not metrics['synchronized']:
            issues.append('Device NTP not synchronized')
        if metrics['stratum'] and metrics['stratum'] > 10:
            issues.append(f'High stratum level: {metrics["stratum"]}')
        if metrics['offset_ms'] and abs(metrics['offset_ms']) > max_offset:
            issues.append(f'Clock offset {metrics["offset_ms"]}ms exceeds {max_offset}ms')
        if metrics['peers'] == 0:
            issues.append('No NTP peers configured')
        
        return {
            'device': device,
            'timestamp': datetime.now().isoformat(),
            'metrics': metrics,
            'status': 'PASS' if not issues else 'FAIL',
            'issues': issues
        }
    
    except NetmikoAuthenticationException:
        logger.error(f"Authentication failed for {device}")
        return {'device': device, 'status': 'FAILED', 'error': 'Authentication failed'}
    except NetmikoTimeoutException:
        logger.error(f"Connection timeout to {device}")
        return {'device': device, 'status': 'FAILED', 'error': 'Connection timeout'}
    except Exception as e:
        logger.error(f"Error validating {device}: {str(e)}")
        return {'device': device, 'status': 'FAILED', 'error': str(e)}


def main():
    parser = argparse.ArgumentParser(
        description='Validate NTP synchronization on network devices',
        epilog=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--device', required=True, help='Device IP or hostname')
    parser.add_argument('-u', '--username', required=True, help='SSH username')
    parser.add_argument('-p', '--password', required=True, help='SSH password')
    parser.add_argument('--device-type', default='cisco_ios',
                        choices=['cisco_ios', 'cisco_xe', 'cisco_nxos'],
                        help='Device OS type (default: cisco_ios)')
    parser.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument('--max-offset', type=float, default=100,
                        help='Maximum acceptable clock offset in ms (default: 100)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    results = validate_ntp(
        device=args.device,
        device_type=args.device_type,
        username=args.username,
        password=args.password,
        max_offset=args.max_offset,
        port=args.port
    )
    
    print(f"\n{'='*60}")
    print(f"NTP Validation Results: {results['device']}")
    print(f"{'='*60}")
    print(f"Status: {results['status']}")
    
    if 'metrics' in results:
        m = results['metrics']
        print(f"Synchronized: {m['synchronized']}")
        if m['stratum']:
            print(f"Stratum: {m['stratum']}")
        if m['offset_ms'] is not None:
            print(f"Clock Offset: {m['offset_ms']} ms")
        print(f"NTP Peers Configured: {m['peers']}")
    
    if results['status'] == 'FAIL':
        print("\nIssues Found:")
        for issue in results.get('issues', []):
            print(f"  - {issue}")
        return 1
    
    print("\nNo issues detected - NTP synchronization is healthy")
    return 0


if __name__ == '__main__':
    sys.exit(main())
```