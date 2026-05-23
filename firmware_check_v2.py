```python
#!/usr/bin/env python3
"""
NTP Configuration Compliance Checker.

Audits NTP configuration on network devices to ensure compliance with
organizational standards (NTP servers, stratum levels, authentication).

Prerequisites:
    - netmiko installed (pip install netmiko)
    - Device SSH access with appropriate credentials
    - Device must support NTP configuration show commands

Usage:
    python ntp_compliance.py -d 192.168.1.1 -u admin -p password -t cisco_ios
    python ntp_compliance.py -d switch.example.com -u admin -k ~/.ssh/id_rsa -t arista_eos --json
"""

import argparse
import json
import logging
import sys
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def parse_ntp_config(output):
    """Parse NTP configuration from device output."""
    ntp_config = {
        'servers': [],
        'authenticate': False,
        'trusted_keys': [],
        'source': None
    }
    
    for line in output.split('\n'):
        line = line.strip()
        if not line or line.startswith('!'):
            continue
        
        if line.startswith('ntp server'):
            parts = line.split()
            if len(parts) >= 3:
                ntp_config['servers'].append({
                    'address': parts[2],
                    'prefer': 'prefer' in line,
                    'source': next((p for p in parts if 'source' in p.lower()), None)
                })
        
        if 'ntp authenticate' in line:
            ntp_config['authenticate'] = True
        
        if line.startswith('ntp trusted-key'):
            key = line.split()[-1]
            ntp_config['trusted_keys'].append(key)
        
        if 'ntp source' in line:
            ntp_config['source'] = line.split()[-1]
    
    return ntp_config


def check_compliance(ntp_config):
    """Verify NTP configuration against compliance standards."""
    issues = []
    warnings = []
    
    if len(ntp_config['servers']) < 2:
        issues.append('Less than 2 NTP servers configured')
    
    if not ntp_config['authenticate']:
        warnings.append('NTP authentication not enabled')
    
    if not any(s['prefer'] for s in ntp_config['servers']):
        warnings.append('No preferred NTP server configured')
    
    for server in ntp_config['servers']:
        if server['address'].startswith(('10.', '192.168.', '172.16.')):
            if not ntp_config['source']:
                warnings.append(f"Private NTP server {server['address']} without source interface")
    
    return {
        'compliant': len(issues) == 0,
        'critical_issues': issues,
        'warnings': warnings
    }


def main():
    parser = argparse.ArgumentParser(description='Check NTP configuration compliance')
    parser.add_argument('-d', '--device', required=True, help='Device IP or hostname')
    parser.add_argument('-u', '--username', required=True, help='SSH username')
    parser.add_argument('-p', '--password', help='SSH password')
    parser.add_argument('-k', '--key-file', help='SSH private key file')
    parser.add_argument('-t', '--device-type', default='cisco_ios', help='Netmiko device type')
    parser.add_argument('--json', action='store_true', help='Output JSON format')
    parser.add_argument('--timeout', type=int, default=10, help='Connection timeout')
    
    args = parser.parse_args()
    
    if not args.password and not args.key_file:
        logger.error('Provide either --password or --key-file')
        sys.exit(1)
    
    device_params = {
        'device_type': args.device_type,
        'host': args.device,
        'username': args.username,
        'timeout': args.timeout,
    }
    
    if args.password:
        device_params['password'] = args.password
    if args.key_file:
        device_params['use_keys'] = True
        device_params['key_file'] = args.key_file
    
    try:
        logger.info(f'Connecting to {args.device}')
        net_connect = ConnectHandler(**device_params)
        
        output = net_connect.send_command('show run | include ntp')
        ntp_config = parse_ntp_config(output)
        compliance = check_compliance(ntp_config)
        
        result = {
            'device': args.device,
            'ntp_servers': ntp_config['servers'],
            'ntp_source': ntp_config['source'],
            'authentication_enabled': ntp_config['authenticate'],
            'compliance': compliance
        }
        
        net_connect.disconnect()
        
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f'\nNTP Compliance Report - {args.device}')
            print('='*60)
            print(f"NTP Servers Configured: {len(ntp_config['servers'])}")
            for srv in ntp_config['servers']:
                prefer = ' (PREFER)' if srv['prefer'] else ''
                print(f"  - {srv['address']}{prefer}")
            print(f"NTP Source Interface: {ntp_config['source'] or 'Not configured'}")
            print(f"Authentication Enabled: {ntp_config['authenticate']}")
            print(f"Compliance Status: {'PASS' if compliance['compliant'] else 'FAIL'}")
            
            if compliance['critical_issues']:
                print('\nCritical Issues:')
                for issue in compliance['critical_issues']:
                    print(f"  ✗ {issue}")
            
            if compliance['warnings']:
                print('\nWarnings:')
                for warning in compliance['warnings']:
                    print(f"  ⚠ {warning}")
            print('='*60)
    
    except NetmikoAuthenticationException as e:
        logger.error(f'Authentication failed: {e}')
        sys.exit(1)
    except NetmikoTimeoutException as e:
        logger.error(f'Connection timeout: {e}')
        sys.exit(1)
    except Exception as e:
        logger.error(f'Error: {e}')
        sys.exit(1)


if __name__ == '__main__':
    main()
```