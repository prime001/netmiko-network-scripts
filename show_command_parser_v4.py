```python
#!/usr/bin/env python3
"""
Interface Performance Monitor - Identify problematic network interfaces.

Purpose:
    Connects to network devices and analyzes interface statistics to identify
    performance issues, errors, and anomalies. Generates a report of interfaces
    with high error rates or down status for troubleshooting and monitoring.

Usage:
    python3 interface_monitor.py --device 192.168.1.1 --username admin \\
        --device-type cisco_ios [--password SECRET] [--error-threshold 50]

Prerequisites:
    - netmiko installed (pip install netmiko)
    - Network device SSH access enabled
    - User credentials with read permissions
    - Supported device type available in netmiko (cisco_ios, junos, arista_eos, etc.)
"""

import argparse
import getpass
import logging
import re
import sys

from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def connect_device(host, username, password, device_type, timeout=30):
    """
    Establish SSH connection to network device.

    Args:
        host: Device IP or hostname
        username: SSH username
        password: SSH password
        device_type: Netmiko device type
        timeout: Connection timeout in seconds

    Returns:
        Connected device object

    Raises:
        NetMikoAuthenticationException: Authentication failure
        NetMikoTimeoutException: Connection timeout
    """
    logger.info(f"Connecting to {host} ({device_type})")
    device = ConnectHandler(
        host=host,
        username=username,
        password=password,
        device_type=device_type,
        timeout=timeout
    )
    logger.info(f"Connected to {host}")
    return device


def parse_interface_data(output):
    """
    Parse interface statistics from device output.

    Args:
        output: Raw interface statistics output from device

    Returns:
        List of dictionaries with interface metrics
    """
    interfaces = []
    blocks = re.split(r'^(\S+)\s', output, flags=re.MULTILINE)[1:]

    for i in range(0, len(blocks), 2):
        if i + 1 >= len(blocks):
            break

        iface_name = blocks[i]
        iface_data = blocks[i + 1]

        iface = {
            'name': iface_name,
            'status': 'unknown',
            'errors': 0,
            'discards': 0,
            'down': False
        }

        for line in iface_data.split('\n'):
            line = line.strip()

            if re.search(r'\bdown\b', line, re.IGNORECASE):
                iface['down'] = True

            errors_match = re.search(r'(\d+)\s+input errors', line)
            if errors_match:
                iface['errors'] += int(errors_match.group(1))

            errors_match = re.search(r'(\d+)\s+output errors', line)
            if errors_match:
                iface['errors'] += int(errors_match.group(1))

            crc_match = re.search(r'(\d+)\s+crc', line, re.IGNORECASE)
            if crc_match:
                iface['errors'] += int(crc_match.group(1))

            collision_match = re.search(r'(\d+)\s+collision', line)
            if collision_match:
                iface['errors'] += int(collision_match.group(1))

            discard_match = re.search(r'(\d+)\s+discards?', line)
            if discard_match:
                iface['discards'] = int(discard_match.group(1))

        if iface['name']:
            interfaces.append(iface)

    return interfaces


def analyze_interfaces(device):
    """
    Gather and parse interface statistics from device.

    Args:
        device: Connected netmiko device object

    Returns:
        List of interface statistics dictionaries
    """
    logger.info("Gathering interface statistics")
    output = device.send_command("show interfaces")
    return parse_interface_data(output)


def report_results(interfaces, error_threshold):
    """
    Generate and display interface issue report.

    Args:
        interfaces: List of interface statistics
        error_threshold: Minimum error count to flag an interface
    """
    problematic = [
        iface for iface in interfaces
        if iface['down'] or iface['errors'] >= error_threshold
    ]

    if problematic:
        print("\n" + "=" * 75)
        print("INTERFACE ISSUES DETECTED")
        print("=" * 75)
        print(f"{'Interface':<20} {'Status':<12} {'Errors':<12} {'Discards':<12}")
        print("-" * 75)

        for iface in sorted(problematic, key=lambda x: x['errors'], reverse=True):
            status = "DOWN" if iface['down'] else "UP"
            print(f"{iface['name']:<20} {status:<12} {iface['errors']:<12} "
                  f"{iface['discards']:<12}")
        print("=" * 75 + "\n")
    else:
        print("\nNo interface issues detected within threshold.\n")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor network device interfaces for errors and issues'
    )
    parser.add_argument('--device', required=True,
                       help='Device IP address or hostname')
    parser.add_argument('--username', required=True, help='SSH username')
    parser.add_argument('--password', help='SSH password (prompt if omitted)')
    parser.add_argument('--device-type', default='cisco_ios',
                       help='Netmiko device type (default: cisco_ios)')
    parser.add_argument('--error-threshold', type=int, default=10,
                       help='Error threshold to flag interface (default: 10)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Connection timeout in seconds (default: 30)')

    args = parser.parse_args()

    if not args.password:
        args.password = getpass.getpass('SSH Password: ')

    try:
        device = connect_device(args.device, args.username, args.password,
                               args.device_type, args.timeout)
        interfaces = analyze_interfaces(device)
        report_results(interfaces, args.error_threshold)
        device.disconnect()
        logger.info("Disconnected from device")

    except (NetMikoAuthenticationException, NetMikoTimeoutException) as e:
        logger.error(f"Connection error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
```