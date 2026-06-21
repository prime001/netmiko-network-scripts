```python
#!/usr/bin/env python3
"""
Interface Error Detector - Identifies problematic network interfaces.

Purpose:
    Connects to network devices and analyzes interface statistics to identify
    ports with errors, discards, or other anomalies. Generates a report of
    problematic interfaces that may indicate hardware or configuration issues.

Usage:
    python interface_error_detector.py -d 192.168.1.1 -u admin -p password
    python interface_error_detector.py -i devices.txt -u admin -p password

Prerequisites:
    - netmiko library: pip install netmiko
    - Network credentials with read access to devices
    - SSH access on port 22

Arguments:
    --device/-d: Single device IP address
    --input/-i: File with list of device IPs (one per line)
    --username/-u: Device username
    --password/-p: Device password
    --device-type/-t: Netmiko device type (default: cisco_ios)
"""

import logging
import argparse
import sys
import os
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def connect_device(host, username, password, device_type, port=22):
    """Connect to network device via SSH."""
    try:
        device = ConnectHandler(
            device_type=device_type,
            host=host,
            username=username,
            password=password,
            port=port,
            timeout=20
        )
        logger.info(f"Connected to {host}")
        return device
    except (NetmikoAuthenticationException, NetmikoTimeoutException) as e:
        logger.error(f"Failed to connect to {host}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error connecting to {host}: {e}")
        return None


def parse_cisco_interfaces(output):
    """Parse 'show interface' output for error statistics."""
    interfaces = {}
    current_iface = None
    
    for line in output.split('\n'):
        line = line.strip()
        if line and line[0] in ('*', ' ') and ' is ' in line:
            current_iface = line.split()[0].lstrip('*')
            interfaces[current_iface] = {'errors': 0, 'discards': 0}
        
        if current_iface:
            if 'input errors' in line.lower():
                try:
                    errors = int(line.split(',')[0].split()[0])
                    interfaces[current_iface]['errors'] = errors
                except (ValueError, IndexError):
                    pass
            if 'discards' in line.lower() and 'input' in line.lower():
                try:
                    parts = line.split(',')
                    for part in parts:
                        if 'discards' in part.lower():
                            discards = int(part.split()[0])
                            interfaces[current_iface]['discards'] = discards
                            break
                except (ValueError, IndexError):
                    pass
    
    return {iface: stats for iface, stats in interfaces.items() 
            if stats['errors'] > 0 or stats['discards'] > 0}


def analyze_device(device, device_type):
    """Gather interface statistics from device."""
    try:
        if 'cisco' in device_type.lower():
            output = device.send_command('show interface')
            return parse_cisco_interfaces(output)
        logger.warning(f"Device type {device_type} not fully supported")
        return {}
    except Exception as e:
        logger.error(f"Error analyzing device: {e}")
        return {}


def load_devices(filename):
    """Load device IPs from file."""
    try:
        with open(filename, 'r') as f:
            devices = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        logger.info(f"Loaded {len(devices)} devices from {filename}")
        return devices
    except FileNotFoundError:
        logger.error(f"File not found: {filename}")
        return []


def print_report(results):
    """Display interface error report."""
    print("\n" + "="*70)
    print("INTERFACE ERROR DETECTION REPORT")
    print("="*70)
    
    total_problems = 0
    for device, interfaces in results.items():
        if interfaces:
            print(f"\n{device}:")
            print(f"{'Interface':<20} {'Errors':<15} {'Discards':<15}")
            print("-"*70)
            for iface, stats in interfaces.items():
                print(f"{iface:<20} {stats['errors']:<15} {stats['discards']:<15}")
                total_problems += 1
        else:
            print(f"\n{device}: No problematic interfaces")
    
    print("\n" + "="*70)
    print(f"Total problematic interfaces: {total_problems}")
    print("="*70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description='Detect and report network interface errors and discards'
    )
    parser.add_argument('-d', '--device', help='Single device IP address')
    parser.add_argument('-i', '--input', help='File with device IPs (one per line)')
    parser.add_argument('-u', '--username', required=True, help='Device username')
    parser.add_argument('-p', '--password', help='Device password')
    parser.add_argument('-t', '--device-type', default='cisco_ios', help='Device type for netmiko')
    parser.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
    
    args = parser.parse_args()
    
    if not args.device and not args.input:
        parser.error('Provide either --device or --input')
    
    password = args.password or os.environ.get('SSH_PASSWORD')
    if not password:
        parser.error('Password required (use -p or SSH_PASSWORD environment variable)')
    
    devices = [args.device] if args.device else load_devices(args.input)
    if not devices:
        logger.error('No devices to process')
        sys.exit(1)
    
    results = {}
    for host in devices:
        device = connect_device(host, args.username, password, args.device_type, args.port)
        if device:
            try:
                results[host] = analyze_device(device, args.device_type)
            finally:
                device.disconnect()
                logger.info(f"Disconnected from {host}")
    
    print_report(results)


if __name__ == '__main__':
    main()
```