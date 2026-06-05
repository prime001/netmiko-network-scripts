```python
#!/usr/bin/env python3
"""
Interface Performance Monitor

Connects to network devices and monitors interface statistics including
errors, discards, and collision rates. Alerts when metrics exceed configured
thresholds.

Usage:
    python interface_monitor.py --device 192.168.1.1 --username admin \
        --password secret --device-type cisco_ios

Prerequisites:
    - netmiko library installed
    - SSH/Telnet access to network devices
    - Device credentials with read-only access sufficient
    - Supported device types: cisco_ios, arista_eos, juniper_junos, etc.

Thresholds:
    - Input errors > 100
    - Output errors > 100
    - Discards > 50
    - CRC errors > 50 (Cisco)
"""

import argparse
import logging
import sys
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from getpass import getpass

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

THRESHOLDS = {
    'input_errors': 100,
    'output_errors': 100,
    'discards': 50,
    'crc_errors': 50,
}


def get_device_connection(device_dict):
    """Establish SSH connection to network device."""
    try:
        logger.info(f"Connecting to {device_dict['host']}...")
        conn = ConnectHandler(**device_dict)
        logger.info(f"Successfully connected to {device_dict['host']}")
        return conn
    except NetmikoTimeoutException:
        logger.error(f"Timeout connecting to {device_dict['host']}")
        sys.exit(1)
    except NetmikoAuthenticationException:
        logger.error(f"Authentication failed for {device_dict['host']}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


def parse_cisco_interfaces(output):
    """Parse Cisco 'show interfaces' output for error stats."""
    interfaces = {}
    current_interface = None
    
    for line in output.split('\n'):
        if line and not line[0].isspace():
            current_interface = line.split()[0]
            interfaces[current_interface] = {
                'input_errors': 0,
                'output_errors': 0,
                'discards': 0,
                'crc_errors': 0,
            }
        elif current_interface and 'input errors' in line.lower():
            parts = line.split(',')
            for part in parts:
                part = part.strip()
                if 'input errors' in part.lower():
                    interfaces[current_interface]['input_errors'] = int(part.split()[-1])
                elif 'output errors' in part.lower():
                    interfaces[current_interface]['output_errors'] = int(part.split()[-1])
                elif 'discards' in part.lower():
                    interfaces[current_interface]['discards'] = int(part.split()[-1])
                elif 'crc' in part.lower():
                    interfaces[current_interface]['crc_errors'] = int(part.split()[-1])
    
    return interfaces


def monitor_interfaces(conn, device_type):
    """Retrieve and analyze interface statistics."""
    try:
        if 'cisco' in device_type.lower():
            output = conn.send_command('show interfaces')
            interfaces = parse_cisco_interfaces(output)
        else:
            logger.warning(f"Device type {device_type} parsing not fully implemented")
            interfaces = {}
        
        return interfaces
    except Exception as e:
        logger.error(f"Error retrieving interface stats: {e}")
        return {}


def check_thresholds(interfaces):
    """Compare interface statistics against configured thresholds."""
    alerts = []
    
    for iface_name, stats in interfaces.items():
        for metric, threshold in THRESHOLDS.items():
            if metric in stats and stats[metric] > threshold:
                alerts.append({
                    'interface': iface_name,
                    'metric': metric,
                    'value': stats[metric],
                    'threshold': threshold,
                })
    
    return alerts


def generate_report(device_host, interfaces, alerts):
    """Print formatted report of interface statistics."""
    print(f"\n{'='*70}")
    print(f"Interface Performance Report - {device_host}")
    print(f"{'='*70}\n")
    
    if not interfaces:
        print("No interface data retrieved.\n")
        return
    
    if alerts:
        print(f"ALERTS: {len(alerts)} threshold(s) exceeded\n")
        for alert in alerts:
            print(f"  [{alert['interface']}] {alert['metric']}: {alert['value']} "
                  f"(threshold: {alert['threshold']})")
        print()
    else:
        print("✓ All interfaces within normal parameters\n")
    
    print("Interface Summary:")
    print(f"{'Interface':<15} {'Input Err':<12} {'Output Err':<12} {'Discards':<12}")
    print("-" * 50)
    for iface_name, stats in list(interfaces.items())[:10]:
        print(f"{iface_name:<15} {stats.get('input_errors', 0):<12} "
              f"{stats.get('output_errors', 0):<12} {stats.get('discards', 0):<12}")


def main():
    parser = argparse.ArgumentParser(
        description='Monitor network device interface statistics'
    )
    parser.add_argument('--device', required=True, help='Device IP address or hostname')
    parser.add_argument('--username', required=True, help='SSH username')
    parser.add_argument('--password', help='SSH password (will prompt if not provided)')
    parser.add_argument('--device-type', required=True,
                       help='Netmiko device type (cisco_ios, arista_eos, etc.)')
    parser.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument('--timeout', type=int, default=10, help='Connection timeout (default: 10s)')
    
    args = parser.parse_args()
    
    password = args.password or getpass('SSH Password: ')
    
    device_dict = {
        'device_type': args.device_type,
        'host': args.device,
        'username': args.username,
        'password': password,
        'port': args.port,
        'timeout': args.timeout,
    }
    
    conn = get_device_connection(device_dict)
    
    try:
        interfaces = monitor_interfaces(conn, args.device_type)
        alerts = check_thresholds(interfaces)
        generate_report(args.device, interfaces, alerts)
        
        if alerts:
            logger.warning(f"{len(alerts)} interface alert(s) found")
            sys.exit(0)
    finally:
        conn.disconnect()
        logger.info("Disconnected from device")


if __name__ == '__main__':
    main()
```