```python
"""
Interface Statistics Collector and Analyzer

Collects interface statistics from network devices and identifies problematic interfaces.

Purpose:
    Connects to network devices, collects interface statistics including errors,
    discards, and bandwidth utilization, then generates a report identifying
    interfaces with potential issues based on configurable thresholds.

Usage:
    python interface_stats_collector.py --device 192.168.1.1 \
        --device_type cisco_ios --username admin --password secret \
        --error_threshold 100 --discard_threshold 50

Prerequisites:
    - netmiko library installed
    - Device must be reachable and have SSH/CLI access enabled
    - Device credentials with read access
    - Interface statistics available via show commands (e.g., show interfaces)

Author: Network Automation Team
"""

import logging
import argparse
import re
from typing import Dict, List, Tuple
from netmiko import ConnectHandler


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_cisco_interfaces(output: str) -> Dict[str, Dict]:
    """Parse Cisco 'show interfaces' output into structured data."""
    interfaces = {}
    
    current_interface = None
    current_data = {}
    
    for line in output.split('\n'):
        if re.match(r'^(\S+)\s+is\s+(up|down)', line):
            if current_interface:
                interfaces[current_interface] = current_data
            
            match = re.match(r'^(\S+)\s+is\s+(up|down)', line)
            current_interface = match.group(1)
            current_data = {
                'status': match.group(2),
                'packets_in': 0,
                'packets_out': 0,
                'input_errors': 0,
                'output_errors': 0,
                'input_discards': 0,
                'output_discards': 0,
            }
        
        if current_interface:
            packets_in = re.search(r'(\d+)\s+packets input', line)
            if packets_in:
                current_data['packets_in'] = int(packets_in.group(1))
            
            packets_out = re.search(r'(\d+)\s+packets output', line)
            if packets_out:
                current_data['packets_out'] = int(packets_out.group(1))
            
            input_errors = re.search(r'(\d+)\s+input errors', line)
            if input_errors:
                current_data['input_errors'] = int(input_errors.group(1))
            
            output_errors = re.search(r'(\d+)\s+output errors', line)
            if output_errors:
                current_data['output_errors'] = int(output_errors.group(1))
            
            input_discards = re.search(r'(\d+)\s+input discards', line)
            if input_discards:
                current_data['input_discards'] = int(input_discards.group(1))
            
            output_discards = re.search(r'(\d+)\s+output discards', line)
            if output_discards:
                current_data['output_discards'] = int(output_discards.group(1))
    
    if current_interface:
        interfaces[current_interface] = current_data
    
    return interfaces


def identify_issues(
    interfaces: Dict[str, Dict],
    error_threshold: int = 100,
    discard_threshold: int = 50
) -> Dict[str, List[str]]:
    """Identify interfaces with issues based on thresholds."""
    issues = {}
    
    for interface, stats in interfaces.items():
        problems = []
        
        if stats['status'] == 'down':
            problems.append('Interface is administratively or physically down')
        
        if stats['input_errors'] > error_threshold:
            problems.append(
                f'Input errors: {stats["input_errors"]} (threshold: {error_threshold})'
            )
        
        if stats['output_errors'] > error_threshold:
            problems.append(
                f'Output errors: {stats["output_errors"]} (threshold: {error_threshold})'
            )
        
        if stats['input_discards'] > discard_threshold:
            problems.append(
                f'Input discards: {stats["input_discards"]} (threshold: {discard_threshold})'
            )
        
        if stats['output_discards'] > discard_threshold:
            problems.append(
                f'Output discards: {stats["output_discards"]} (threshold: {discard_threshold})'
            )
        
        if problems:
            issues[interface] = problems
    
    return issues


def collect_interface_stats(device_handler: ConnectHandler) -> Dict[str, Dict]:
    """Collect interface statistics from device."""
    try:
        output = device_handler.send_command('show interfaces')
        return parse_cisco_interfaces(output)
    except Exception as e:
        logger.error(f'Error collecting interface statistics: {e}')
        return {}


def print_report(
    device: str,
    interfaces: Dict[str, Dict],
    issues: Dict[str, List[str]]
) -> None:
    """Print formatted statistics report."""
    print(f'\n{"="*80}')
    print(f'Interface Statistics Report - {device}')
    print(f'{"="*80}')
    
    print(f'\nTotal Interfaces: {len(interfaces)}')
    print(f'Interfaces with Issues: {len(issues)}')
    
    if issues:
        print(f'\n{"Interface":<20} {"Issues":<60}')
        print(f'{"-"*80}')
        
        for interface, problems in sorted(issues.items()):
            for i, problem in enumerate(problems):
                if i == 0:
                    print(f'{interface:<20} {problem:<60}')
                else:
                    print(f'{"":<20} {problem:<60}')
    else:
        print('\nNo interfaces with issues detected.')
    
    print(f'\n{"Interface":<20} {"Status":<10} {"Errors":<10} {"Discards":<10}')
    print(f'{"-"*50}')
    
    for interface, stats in sorted(interfaces.items()):
        if interface in issues:
            total_errors = stats['input_errors'] + stats['output_errors']
            total_discards = (
                stats['input_discards'] + stats['output_discards']
            )
            print(
                f'{interface:<20} {stats["status"]:<10} '
                f'{total_errors:<10} {total_discards:<10}'
            )


def main():
    parser = argparse.ArgumentParser(
        description='Collect and analyze interface statistics',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--device', required=True, help='Device IP or hostname')
    parser.add_argument('--username', required=True, help='SSH username')
    parser.add_argument('--password', required=True, help='SSH password')
    parser.add_argument(
        '--device_type',
        default='cisco_ios',
        help='Netmiko device type (default: cisco_ios)'
    )
    parser.add_argument('--port', type=int, default=22, help='SSH port')
    parser.add_argument(
        '--error_threshold',
        type=int,
        default=100,
        help='Error count threshold (default: 100)'
    )
    parser.add_argument(
        '--discard_threshold',
        type=int,
        default=50,
        help='Discard count threshold (default: 50)'
    )
    
    args = parser.parse_args()
    
    device_params = {
        'device_type': args.device_type,
        'host': args.device,
        'username': args.username,
        'password': args.password,
        'port': args.port,
    }
    
    try:
        logger.info(f'Connecting to {args.device}')
        device = ConnectHandler(**device_params)
        
        logger.info('Collecting interface statistics')
        interfaces = collect_interface_stats(device)
        
        logger.info('Analyzing interface statistics')
        issues = identify_issues(
            interfaces,
            args.error_threshold,
            args.discard_threshold
        )
        
        device.disconnect()
        
        print_report(args.device, interfaces, issues)
        
        logger.info('Analysis completed successfully')
        return 0 if not issues else 1
        
    except Exception as e:
        logger.error(f'Failed to complete analysis: {e}')
        return 1


if __name__ == '__main__':
    exit(main())
```