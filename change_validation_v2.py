```python
"""
Interface Error Monitor - netmiko-based network device interface analyzer.

Purpose:
    Monitors network device interfaces for errors, discards, and CRC failures.
    Generates alerts when error thresholds are exceeded. Useful for detecting
    interface health issues before they impact production traffic.

Usage:
    python interface_error_monitor.py --host 192.168.1.1 --device-type cisco_ios \
        --username admin --password secret --error-threshold 100 --output report.txt

Prerequisites:
    - netmiko library installed (pip install netmiko)
    - Device must be reachable and have SSH enabled
    - Credentials with read access to device
    - Device must support "show interfaces" command (Cisco IOS/XE, NX-OS, etc.)

Author: Network Engineering Portfolio
"""

import argparse
import logging
import sys
from datetime import datetime
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, SSHException


def setup_logging(log_file=None):
    """Configure logging for the script."""
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    handlers = [logging.StreamHandler(sys.stdout)]
    
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=handlers
    )
    return logging.getLogger(__name__)


def connect_to_device(host, device_type, username, password, timeout=30):
    """Establish SSH connection to network device."""
    try:
        device = ConnectHandler(
            device_type=device_type,
            host=host,
            username=username,
            password=password,
            timeout=timeout
        )
        logging.info(f"Successfully connected to {host}")
        return device
    except (NetMikoTimeoutException, SSHException) as e:
        logging.error(f"Failed to connect to {host}: {e}")
        return None


def parse_interface_stats(output):
    """Parse interface error statistics from device output."""
    interfaces = {}
    current_interface = None
    
    for line in output.split('\n'):
        line = line.strip()
        
        if any(line.startswith(prefix) for prefix in 
               ('Ethernet', 'FastEthernet', 'GigabitEthernet', 'Port-channel', 'Vlan')):
            current_interface = line.split()[0]
            interfaces[current_interface] = {
                'input_errors': 0,
                'output_errors': 0,
                'crc': 0
            }
        
        if current_interface and 'input errors' in line.lower():
            try:
                value = int(line.split(',')[0].split()[-1])
                interfaces[current_interface]['input_errors'] = value
            except (ValueError, IndexError):
                pass
        
        if current_interface and 'output errors' in line.lower():
            try:
                value = int(line.split(',')[0].split()[-1])
                interfaces[current_interface]['output_errors'] = value
            except (ValueError, IndexError):
                pass
        
        if current_interface and 'crc' in line.lower():
            try:
                value = int(line.split()[-1])
                interfaces[current_interface]['crc'] = value
            except (ValueError, IndexError):
                pass
    
    return interfaces


def check_error_thresholds(interfaces, threshold):
    """Identify interfaces exceeding error thresholds."""
    problem_interfaces = {}
    
    for interface, stats in interfaces.items():
        if (stats['input_errors'] > threshold or 
            stats['output_errors'] > threshold or 
            stats['crc'] > threshold):
            problem_interfaces[interface] = stats
    
    return problem_interfaces


def generate_report(device_info, interfaces, problem_interfaces, output_file=None):
    """Generate formatted report of interface status."""
    report = []
    report.append(f"\n{'='*70}")
    report.append(f"Interface Error Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Device: {device_info['host']}")
    report.append(f"{'='*70}\n")
    
    if problem_interfaces:
        report.append(f"ALERT: {len(problem_interfaces)} interface(s) with errors:\n")
        for interface, stats in problem_interfaces.items():
            report.append(f"  {interface}:")
            report.append(f"    Input Errors:  {stats['input_errors']}")
            report.append(f"    Output Errors: {stats['output_errors']}")
            report.append(f"    CRC Errors:    {stats['crc']}")
            report.append("")
    else:
        report.append("All monitored interfaces are healthy.\n")
    
    report.append(f"Total interfaces monitored: {len(interfaces)}")
    report.append(f"{'='*70}\n")
    
    report_text = '\n'.join(report)
    print(report_text)
    
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(report_text)
            logging.info(f"Report written to {output_file}")
        except IOError as e:
            logging.error(f"Failed to write report: {e}")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description='Monitor network device interfaces for errors',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Example: %(prog)s --host 192.168.1.1 --device-type cisco_ios '
               '--username admin --password secret'
    )
    
    parser.add_argument('--host', required=True, help='Device IP address')
    parser.add_argument('--device-type', required=True,
                        help='netmiko device type (cisco_ios, cisco_xe, arista_eos, etc.)')
    parser.add_argument('--username', required=True, help='SSH username')
    parser.add_argument('--password', required=True, help='SSH password')
    parser.add_argument('--error-threshold', type=int, default=100,
                        help='Error count threshold for alerting (default: 100)')
    parser.add_argument('--output', help='Output report file path')
    parser.add_argument('--timeout', type=int, default=30,
                        help='Connection timeout in seconds (default: 30)')
    
    args = parser.parse_args()
    
    log_file = args.output.replace('.txt', '.log') if args.output else None
    logger = setup_logging(log_file)
    
    device = connect_to_device(
        args.host,
        args.device_type,
        args.username,
        args.password,
        args.timeout
    )
    
    if not device:
        sys.exit(1)
    
    try:
        logging.info("Gathering interface statistics...")
        output = device.send_command('show interfaces')
        
        interfaces = parse_interface_stats(output)
        problem_interfaces = check_error_thresholds(interfaces, args.error_threshold)
        
        device_info = {'host': args.host}
        generate_report(device_info, interfaces, problem_interfaces, args.output)
        
        sys.exit(1 if problem_interfaces else 0)
    
    except Exception as e:
        logging.error(f"Error during execution: {e}")
        sys.exit(1)
    
    finally:
        device.disconnect()
        logging.info("Disconnected from device")


if __name__ == "__main__":
    main()
```