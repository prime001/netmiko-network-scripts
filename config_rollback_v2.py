```python
#!/usr/bin/env python3
"""
Interface Statistics Collector - Network Device Monitoring

Collects interface statistics including errors, discards, and collisions to identify
problematic interfaces. Useful for network health monitoring and troubleshooting.

Prerequisites:
    - netmiko>=4.0.0
    - Network device SSH access enabled
    - Valid device credentials with read privileges

Usage:
    python interface_stats_collector.py --device 10.1.1.1 --user admin --device-type cisco_ios
    python interface_stats_collector.py --device core1.example.com -u netadmin -f creds.txt --device-type arista_eos

Examples:
    # Interactive password prompt
    python interface_stats_collector.py --device 192.168.1.1 --user admin --device-type cisco_ios

    # Use password file
    python interface_stats_collector.py --device 192.168.1.1 --user admin -f ~/.ssh/pass --device-type cisco_ios

    # With custom error threshold
    python interface_stats_collector.py --device 192.168.1.1 --user admin --device-type cisco_ios --threshold 5
"""

import argparse
import logging
import sys
from getpass import getpass
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoException


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def get_credentials(args):
    """Get credentials from command-line args or user input."""
    username = args.user

    if args.password_file:
        try:
            with open(args.password_file, 'r') as f:
                password = f.read().strip()
        except FileNotFoundError:
            logger.error(f"Password file not found: {args.password_file}")
            sys.exit(1)
    elif args.password:
        password = args.password
    else:
        password = getpass(f"Password for {username}: ")

    return username, password


def collect_interface_stats(device_ip, device_type, username, password):
    """Connect to device and collect interface statistics."""
    try:
        logger.info(f"Connecting to {device_ip}...")
        device = ConnectHandler(
            host=device_ip,
            device_type=device_type,
            username=username,
            password=password,
            timeout=15
        )
        logger.info(f"Connected to {device_ip}")

        logger.info("Collecting interface statistics...")
        if 'cisco' in device_type:
            output = device.send_command('show interfaces')
        elif 'arista' in device_type:
            output = device.send_command('show interfaces')
        else:
            output = device.send_command('show interfaces')

        device.disconnect()
        return output

    except NetmikoException as e:
        logger.error(f"Connection failed: {e}")
        sys.exit(1)


def parse_interface_output(output):
    """Parse interface output and extract error statistics."""
    interfaces = {}
    current_interface = None

    for line in output.split('\n'):
        if line and not line[0].isspace() and line.split():
            current_interface = line.split()[0]
            interfaces[current_interface] = {
                'errors': 0,
                'discards': 0,
                'collisions': 0
            }

        elif current_interface and current_interface in interfaces:
            line_lower = line.lower()

            if 'input errors' in line_lower:
                try:
                    interfaces[current_interface]['errors'] = int(line.split()[0])
                except (ValueError, IndexError):
                    pass

            elif 'input discards' in line_lower:
                try:
                    interfaces[current_interface]['discards'] = int(line.split()[0])
                except (ValueError, IndexError):
                    pass

            elif 'collisions' in line_lower:
                try:
                    interfaces[current_interface]['collisions'] = int(line.split()[0])
                except (ValueError, IndexError):
                    pass

    return interfaces


def print_report(interfaces, threshold):
    """Print formatted interface statistics report."""
    problem_intfs = [
        (name, stats) for name, stats in interfaces.items()
        if stats['errors'] >= threshold or stats['discards'] >= threshold
    ]

    print("\n" + "=" * 70)
    print("INTERFACE STATISTICS REPORT")
    print("=" * 70)

    if problem_intfs:
        print(f"\nInterfaces exceeding threshold ({threshold}):\n")
        print(f"{'Interface':<15} {'Errors':<12} {'Discards':<12} {'Collisions':<12}")
        print("-" * 51)

        for intf, stats in sorted(problem_intfs):
            print(f"{intf:<15} {stats['errors']:<12} {stats['discards']:<12} {stats['collisions']:<12}")
    else:
        print(f"\nNo interfaces found with errors/discards >= {threshold}")

    total = len(interfaces)
    problem = len(problem_intfs)
    print(f"\nTotal: {total} interfaces | Issues: {problem}\n")
    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--device', required=True, help='Device IP or hostname')
    parser.add_argument('--user', '-u', required=True, help='SSH username')
    parser.add_argument('--password', '-p', help='SSH password (omit for prompt)')
    parser.add_argument('--password-file', '-f', help='File containing password')
    parser.add_argument('--device-type', required=True,
                        choices=['cisco_ios', 'cisco_xe', 'cisco_nxos',
                                'arista_eos', 'juniper_junos'],
                        help='Device OS type')
    parser.add_argument('--threshold', type=int, default=10,
                        help='Minimum errors/discards to report (default: 10)')

    args = parser.parse_args()

    try:
        username, password = get_credentials(args)
        output = collect_interface_stats(
            args.device, args.device_type, username, password
        )

        interfaces = parse_interface_output(output)
        print_report(interfaces, args.threshold)

    except KeyboardInterrupt:
        logger.info("\nScript interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
```