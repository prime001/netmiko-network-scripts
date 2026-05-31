#!/usr/bin/env python3
"""
Configuration Backup and Diff Tool

Captures running configuration from network devices, compares with previous
backups, and displays differences. Useful for change management and auditing.

Usage:
    python config_backup_diff.py --device 192.168.1.1 --username admin --password secret
    python config_backup_diff.py --device 10.0.0.1 -u admin -p secret --backup-dir ./backups

Prerequisites:
    - netmiko library installed
    - Network device accessible via SSH (TCP port 22 or custom)
    - Valid credentials with enable/admin privileges
    - Python 3.7+

Examples:
    # Backup Cisco device and compare with previous version
    ./config_backup_diff.py --device router1.example.com -u netadmin -p mypass123

    # Specify non-standard SSH port and backup directory
    ./config_backup_diff.py --device 192.168.1.1 -u admin -p pass --port 2222 --backup-dir /var/backups/configs

The script automatically stores timestamped backups and displays unified diff
output when previous backups exist.
"""

import argparse
import difflib
import logging
import sys
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException


def setup_logging(verbose=False):
    """Configure logging with timestamp and level information."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)


def get_device_config(device_params, logger):
    """
    Connect to device and retrieve running configuration.
    
    Args:
        device_params: Dictionary with connection parameters for netmiko
        logger: Logger instance for status messages
        
    Returns:
        Configuration string on success, None on failure
    """
    try:
        logger.info(f"Connecting to {device_params['host']}")
        connection = ConnectHandler(**device_params)
        
        logger.info("Retrieving running configuration")
        config = connection.send_command("show running-config")
        
        connection.disconnect()
        logger.info("Successfully retrieved configuration")
        return config
        
    except NetmikoTimeoutException:
        logger.error(f"Timeout connecting to {device_params['host']}")
        return None
    except NetmikoAuthenticationException:
        logger.error(f"Authentication failed for {device_params['host']}")
        return None
    except Exception as e:
        logger.error(f"Error retrieving configuration: {e}")
        return None


def find_previous_backup(device_name, backup_dir):
    """
    Locate the most recent backup file for a device.
    
    Args:
        device_name: Device hostname or IP address
        backup_dir: Directory containing backup files
        
    Returns:
        Path object to previous backup or None if not found
    """
    backup_dir = Path(backup_dir)
    if not backup_dir.exists():
        return None
    
    pattern = f"{device_name}_*.backup"
    backups = sorted(backup_dir.glob(pattern))
    return backups[-1] if backups else None


def save_backup(config, device_name, backup_dir, logger):
    """
    Persist configuration backup with ISO timestamp.
    
    Args:
        config: Configuration string content
        device_name: Device hostname or IP
        backup_dir: Directory for storing backups
        logger: Logger instance
        
    Returns:
        Path object to saved backup file
    """
    backup_dir = Path(backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = backup_dir / f"{device_name}_{timestamp}.backup"
    
    with open(filename, 'w') as f:
        f.write(config)
    
    logger.info(f"Configuration saved to {filename}")
    return filename


def display_diff(old_config, new_config, device_name):
    """
    Display unified diff between two configurations.
    
    Args:
        old_config: Previous configuration content
        new_config: Current configuration content
        device_name: Device identifier for output header
    """
    old_lines = old_config.splitlines(keepends=True)
    new_lines = new_config.splitlines(keepends=True)
    
    diff = list(difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"{device_name} (previous)",
        tofile=f"{device_name} (current)",
        lineterm=''
    ))
    
    print(f"\n{'='*70}")
    print(f"Configuration Comparison - {device_name}")
    print(f"{'='*70}\n")
    
    if not diff:
        print("No configuration changes detected.\n")
    else:
        print(''.join(diff))


def main():
    """Parse arguments, execute backup/compare workflow."""
    parser = argparse.ArgumentParser(
        description='Backup device config and compare with previous version'
    )
    parser.add_argument('--device', required=True,
                        help='Device IP address or hostname')
    parser.add_argument('-u', '--username', required=True,
                        help='SSH username')
    parser.add_argument('-p', '--password', required=True,
                        help='SSH password')
    parser.add_argument('-t', '--device-type', default='cisco_ios',
                        help='Netmiko device type (default: cisco_ios)')
    parser.add_argument('--backup-dir', default='./config_backups',
                        help='Directory for storing backups (default: ./config_backups)')
    parser.add_argument('--port', type=int, default=22,
                        help='SSH port (default: 22)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose logging')
    
    args = parser.parse_args()
    logger = setup_logging(args.verbose)
    
    device_params = {
        'device_type': args.device_type,
        'host': args.device,
        'username': args.username,
        'password': args.password,
        'port': args.port,
        'timeout': 30,
        'conn_timeout': 30,
    }
    
    # Retrieve current configuration
    current_config = get_device_config(device_params, logger)
    if not current_config:
        logger.error("Failed to retrieve configuration from device")
        sys.exit(1)
    
    # Compare with previous backup if available
    previous_backup_path = find_previous_backup(args.device, args.backup_dir)
    if previous_backup_path:
        logger.info(f"Found previous backup: {previous_backup_path}")
        with open(previous_backup_path, 'r') as f:
            previous_config = f.read()
        display_diff(previous_config, current_config, args.device)
    else:
        logger.info("No previous backup found - first backup for this device")
    
    # Save current configuration
    save_backup(current_config, args.device, args.backup_dir, logger)


if __name__ == "__main__":
    main()