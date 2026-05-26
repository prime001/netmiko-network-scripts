```python
"""
Interface Error and Discard Monitor - Analyzes network device interface health.

Connects to network devices, retrieves interface statistics, identifies
interfaces with excessive errors and discards, and generates health reports.
Useful for troubleshooting link quality issues and interface failures.

Usage:
    python interface_monitor.py --device 192.168.1.1 --username admin \
        --password secret --error-threshold 100 --discard-threshold 50

Prerequisites:
    - netmiko
    - Python 3.6+
    - SSH access to devices
    - Support for "show interfaces" command

Supported Devices:
    - Cisco IOS/IOS-XE
    - Cisco IOS-XR
    - Arista EOS
    - Juniper Junos
"""

import argparse
import logging
import json
import re
from netmiko import ConnectHandler

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)


def parse_cisco_interfaces(output):
    """Parse Cisco 'show interfaces' output for error statistics."""
    interfaces = {}
    current_interface = None

    for line in output.split('\n'):
        # Match interface name line
        interface_match = re.match(r'^(\S+)\s+is\s+(up|down)', line)
        if interface_match:
            current_interface = interface_match.group(1)
            interfaces[current_interface] = {
                'name': current_interface,
                'status': interface_match.group(2),
                'input_errors': 0,
                'output_errors': 0,
                'input_discards': 0,
                'output_discards': 0,
                'crc_errors': 0,
            }
            continue

        if not current_interface:
            continue

        # Extract input errors
        input_err_match = re.search(r'(\d+)\s+input errors', line)
        if input_err_match:
            interfaces[current_interface]['input_errors'] = int(input_err_match.group(1))

        # Extract output errors
        output_err_match = re.search(r'(\d+)\s+output errors', line)
        if output_err_match:
            interfaces[current_interface]['output_errors'] = int(output_err_match.group(1))

        # Extract input discards
        input_discard_match = re.search(r'(\d+)\s+input discards', line)
        if input_discard_match:
            interfaces[current_interface]['input_discards'] = int(input_discard_match.group(1))

        # Extract output discards
        output_discard_match = re.search(r'(\d+)\s+output discards', line)
        if output_discard_match:
            interfaces[current_interface]['output_discards'] = int(output_discard_match.group(1))

        # Extract CRC errors
        crc_match = re.search(r'(\d+)\s+CRC', line)
        if crc_match:
            interfaces[current_interface]['crc_errors'] = int(crc_match.group(1))

    return interfaces


def analyze_device_interfaces(host, username, password, device_type,
                             error_threshold, discard_threshold):
    """
    Connect to device and analyze interface health.

    Args:
        host: Device IP address
        username: SSH username
        password: SSH password
        device_type: netmiko device type string
        error_threshold: Minimum error count to flag interface
        discard_threshold: Minimum discard count to flag interface

    Returns:
        dict: Analysis report with unhealthy interfaces
    """
    try:
        logger.info(f"Connecting to {host} ({device_type})")
        device = ConnectHandler(
            host=host,
            username=username,
            password=password,
            device_type=device_type,
            timeout=30,
            conn_timeout=10
        )

        logger.info(f"Retrieving interface statistics from {host}")
        output = device.send_command("show interfaces")
        device.disconnect()

        interfaces = parse_cisco_interfaces(output)

        # Identify unhealthy interfaces
        unhealthy = []
        for int_name, stats in interfaces.items():
            total_errors = stats['input_errors'] + stats['output_errors']
            total_discards = stats['input_discards'] + stats['output_discards']

            if total_errors >= error_threshold or total_discards >= discard_threshold:
                unhealthy.append({
                    'interface': int_name,
                    'status': stats['status'],
                    'input_errors': stats['input_errors'],
                    'output_errors': stats['output_errors'],
                    'input_discards': stats['input_discards'],
                    'output_discards': stats['output_discards'],
                    'crc_errors': stats['crc_errors'],
                    'total_errors': total_errors,
                    'total_discards': total_discards,
                })

        report = {
            'device': host,
            'device_type': device_type,
            'total_interfaces': len(interfaces),
            'unhealthy_count': len(unhealthy),
            'error_threshold': error_threshold,
            'discard_threshold': discard_threshold,
            'unhealthy_interfaces': sorted(unhealthy,
                                          key=lambda x: x['total_errors'],
                                          reverse=True)
        }

        logger.info(f"Analysis complete: {report['unhealthy_count']} "
                   f"unhealthy interfaces found")
        return report

    except Exception as e:
        logger.error(f"Failed to analyze {host}: {str(e)}")
        return None


def print_report(report):
    """Pretty-print analysis report to console."""
    print(f"\n{'='*60}")
    print(f"Interface Health Report: {report['device']}")
    print(f"{'='*60}")
    print(f"Device Type: {report['device_type']}")
    print(f"Total Interfaces: {report['total_interfaces']}")
    print(f"Unhealthy Interfaces: {report['unhealthy_count']}")
    print(f"Thresholds - Errors: {report['error_threshold']}, "
          f"Discards: {report['discard_threshold']}")

    if report['unhealthy_interfaces']:
        print(f"\n{'Interface':<20} {'Status':<10} {'Errors':<10} {'Discards':<10}")
        print("-" * 50)
        for iface in report['unhealthy_interfaces']:
            print(f"{iface['interface']:<20} {iface['status']:<10} "
                  f"{iface['total_errors']:<10} {iface['total_discards']:<10}")
            if iface['crc_errors'] > 0:
                print(f"  └─ CRC Errors: {iface['crc_errors']}")
    else:
        print("\nAll interfaces are healthy.")

    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Monitor network device interface errors and discards"
    )
    parser.add_argument("--device", required=True, help="Device IP address")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument("--device-type", default="cisco_ios",
                       help="netmiko device type (default: cisco_ios)")
    parser.add_argument("--error-threshold", type=int, default=100,
                       help="Flag interfaces with errors >= threshold "
                            "(default: 100)")
    parser.add_argument("--discard-threshold", type=int, default=50,
                       help="Flag interfaces with discards >= threshold "
                            "(default: 50)")
    parser.add_argument("--json", action="store_true",
                       help="Output report as JSON")

    args = parser.parse_args()

    report = analyze_device_interfaces(
        args.device,
        args.username,
        args.password,
        args.device_type,
        args.error_threshold,
        args.discard_threshold
    )

    if not report:
        logger.error("Failed to generate report")
        return 1

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)

    return 0


if __name__ == "__main__":
    exit(main())
```