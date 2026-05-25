#!/usr/bin/env python3
"""
Interface Statistics Analyzer - Collect and analyze interface statistics.

Connects to network devices via SSH and collects interface statistics
including errors, discards, and CRC errors. Identifies interfaces with
issues exceeding specified thresholds and generates a report.

Usage:
    python interface_stats.py -d 192.168.1.1 -u admin -p password

Prerequisites:
    - netmiko: pip install netmiko
    - Device SSH access enabled with proper credentials
"""

import argparse
import logging
import sys
from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException
from netmiko.ssh_autodetect import SSHDetect

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def detect_device_type(host, username, password, timeout=10):
    """Auto-detect device type using netmiko's SSHDetect."""
    try:
        logger.info(f"Detecting device type for {host}...")
        guesser = SSHDetect(host=host, username=username, password=password, timeout=timeout)
        device_type = guesser.autodetect()
        logger.info(f"Detected device type: {device_type}")
        return device_type
    except Exception as e:
        logger.error(f"Auto-detection failed: {e}")
        raise


def connect_device(host, username, password, device_type=None, timeout=30):
    """Establish SSH connection to device."""
    try:
        if not device_type:
            device_type = detect_device_type(host, username, password)
        logger.info(f"Connecting to {host} ({device_type})...")
        device = ConnectHandler(
            device_type=device_type,
            host=host,
            username=username,
            password=password,
            timeout=timeout
        )
        logger.info(f"Connected to {host}")
        return device
    except NetmikoAuthenticationException:
        logger.error(f"Authentication failed for {host}")
        raise
    except NetmikoTimeoutException:
        logger.error(f"Connection timeout for {host}")
        raise


def parse_interface_stats(device, device_type):
    """Parse interface statistics from device output."""
    stats = {}
    try:
        if 'cisco' in device_type.lower():
            output = device.send_command("show interfaces")
            current_intf = None
            for line in output.split('\n'):
                if line and not line[0].isspace():
                    current_intf = line.split()[0]
                    stats[current_intf] = {
                        'input_errors': 0,
                        'output_errors': 0,
                        'input_discards': 0,
                        'output_discards': 0,
                        'crc_errors': 0
                    }
                elif current_intf:
                    try:
                        if 'input errors' in line:
                            stats[current_intf]['input_errors'] = int(line.split(',')[0].split()[-1])
                        elif 'output errors' in line:
                            stats[current_intf]['output_errors'] = int(line.split(',')[0].split()[-1])
                        elif 'input discards' in line:
                            stats[current_intf]['input_discards'] = int(line.split()[-1])
                        elif 'output discards' in line:
                            stats[current_intf]['output_discards'] = int(line.split()[-1])
                        elif 'crc' in line.lower():
                            stats[current_intf]['crc_errors'] = int(line.split(',')[0].split()[-1])
                    except (ValueError, IndexError):
                        pass
        logger.info(f"Parsed {len(stats)} interfaces")
        return stats
    except Exception as e:
        logger.error(f"Error parsing stats: {e}")
        raise


def analyze_stats(stats, error_thresh=10, discard_thresh=5):
    """Analyze stats and identify problematic interfaces."""
    problem_errors = []
    problem_discards = []
    for intf, data in stats.items():
        total_errors = (data.get('input_errors', 0) + 
                       data.get('output_errors', 0) + 
                       data.get('crc_errors', 0))
        total_discards = (data.get('input_discards', 0) + 
                         data.get('output_discards', 0))
        if total_errors >= error_thresh:
            problem_errors.append(f"  {intf}: {total_errors} errors "
                                f"(Input: {data.get('input_errors', 0)}, "
                                f"Output: {data.get('output_errors', 0)}, "
                                f"CRC: {data.get('crc_errors', 0)})")
        if total_discards >= discard_thresh:
            problem_discards.append(f"  {intf}: {total_discards} discards "
                                  f"(Input: {data.get('input_discards', 0)}, "
                                  f"Output: {data.get('output_discards', 0)})")
    return problem_errors, problem_discards


def print_report(host, stats, errors, discards):
    """Print analysis report to stdout."""
    print(f"\n{'='*70}")
    print(f"Interface Statistics Report - {host}")
    print(f"{'='*70}\n")
    print(f"Total Interfaces: {len(stats)}\n")
    if errors:
        print("INTERFACES WITH ERRORS:")
        print("\n".join(errors) + "\n")
    else:
        print("No interfaces with errors above threshold.\n")
    if discards:
        print("INTERFACES WITH DISCARDS:")
        print("\n".join(discards) + "\n")
    else:
        print("No interfaces with discards above threshold.\n")
    print(f"{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Collect and analyze interface statistics from network devices.'
    )
    parser.add_argument('-d', '--device', required=True, help='Device IP/hostname')
    parser.add_argument('-u', '--username', required=True, help='SSH username')
    parser.add_argument('-p', '--password', required=True, help='SSH password')
    parser.add_argument('-t', '--device-type', help='Device type (e.g., cisco_ios)')
    parser.add_argument('--error-threshold', type=int, default=10,
                       help='Error count threshold (default: 10)')
    parser.add_argument('--discard-threshold', type=int, default=5,
                       help='Discard count threshold (default: 5)')
    args = parser.parse_args()
    
    device = None
    try:
        device = connect_device(args.device, args.username, args.password, args.device_type)
        device_type = args.device_type or 'cisco_ios'
        stats = parse_interface_stats(device, device_type)
        errors, discards = analyze_stats(stats, args.error_threshold, args.discard_threshold)
        print_report(args.device, stats, errors, discards)
        return 0 if not errors and not discards else 1
    except Exception as e:
        logger.error(f"Script failed: {e}")
        return 1
    finally:
        if device:
            device.disconnect()
            logger.info("Disconnected from device")


if __name__ == "__main__":
    sys.exit(main())