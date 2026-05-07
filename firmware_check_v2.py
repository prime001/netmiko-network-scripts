```python
#!/usr/bin/env python3
"""
Device Configuration Backup Script

Connects to network devices, backs up running configurations with timestamps,
stores versioned backups, and reports configuration changes. Useful for change
tracking, audit compliance, and configuration versioning.

Usage:
    python backup_config.py --host 192.168.1.1 --device-type cisco_ios \\
        --username admin --password secret --backup-dir ./backups

    python backup_config.py --host 192.168.1.1 --device-type cisco_ios \\
        --username admin --password secret --backup-dir ./backups --show-diff

Prerequisites:
    - netmiko library installed (pip install netmiko)
    - Network connectivity to target devices
    - Appropriate credentials with read privileges
    - SSH or Telnet enabled on devices
"""

import argparse
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from difflib import unified_diff

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, AuthenticationException


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def backup_device_config(device_params, backup_dir):
    """
    Backup running configuration from network device.

    Args:
        device_params (dict): Connection parameters for netmiko
        backup_dir (str): Directory to store backups

    Returns:
        tuple: (config_content, backup_file_path) or (None, None) on failure
    """
    try:
        logger.info(f"Connecting to {device_params['host']}...")
        connection = ConnectHandler(**device_params)
        logger.info(f"Successfully connected to {device_params['host']}")

        logger.info("Retrieving running configuration...")
        running_config = connection.send_command("show running-config")
        connection.disconnect()

        if not running_config:
            logger.error("Failed to retrieve running configuration")
            return None, None

        os.makedirs(backup_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        hostname = device_params['host'].replace('.', '_')
        backup_file = Path(backup_dir) / f"{hostname}_{timestamp}.conf"

        backup_file.write_text(running_config)
        logger.info(f"Configuration backed up to {backup_file}")

        return running_config, backup_file

    except AuthenticationException as e:
        logger.error(f"Authentication failed: {e}")
        return None, None
    except NetmikoTimeoutException as e:
        logger.error(f"Connection timeout: {e}")
        return None, None
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return None, None


def get_previous_backup(backup_dir, hostname):
    """
    Find the most recent previous backup for comparison.

    Args:
        backup_dir (str): Directory containing backups
        hostname (str): Sanitized hostname identifier

    Returns:
        str: Content of previous backup or None
    """
    backup_path = Path(backup_dir)
    if not backup_path.exists():
        return None

    backups = sorted(backup_path.glob(f"{hostname}_*.conf"))
    if len(backups) < 2:
        return None

    try:
        return backups[-2].read_text()
    except Exception as e:
        logger.warning(f"Could not read previous backup: {e}")
        return None


def generate_config_diff(old_config, new_config, hostname):
    """
    Generate unified diff between configurations.

    Args:
        old_config (str): Previous configuration
        new_config (str): Current configuration
        hostname (str): Device hostname for logging

    Returns:
        str: Diff output or empty string if no changes
    """
    if not old_config:
        logger.info(f"No previous backup found for {hostname}")
        return ""

    old_lines = old_config.splitlines(keepends=True)
    new_lines = new_config.splitlines(keepends=True)

    diff = unified_diff(old_lines, new_lines,
                       fromfile=f"{hostname}_previous",
                       tofile=f"{hostname}_current",
                       lineterm='')

    diff_output = ''.join(diff)
    if diff_output:
        logger.info(f"Configuration changes detected on {hostname}")
    else:
        logger.info(f"No configuration changes on {hostname}")

    return diff_output


def main():
    parser = argparse.ArgumentParser(
        description="Backup network device running configurations"
    )
    parser.add_argument('--host', required=True,
                        help='Device IP or hostname')
    parser.add_argument('--device-type', required=True,
                        help='Netmiko device type (cisco_ios, arista_eos, etc)')
    parser.add_argument('--username', required=True,
                        help='SSH username')
    parser.add_argument('--password', required=True,
                        help='SSH password')
    parser.add_argument('--port', type=int, default=22,
                        help='SSH port (default: 22)')
    parser.add_argument('--backup-dir', default='./backups',
                        help='Directory for backup storage (default: ./backups)')
    parser.add_argument('--show-diff', action='store_true',
                        help='Display config diff from previous backup')

    args = parser.parse_args()

    device_params = {
        'device_type': args.device_type,
        'host': args.host,
        'username': args.username,
        'password': args.password,
        'port': args.port,
        'timeout': 30,
    }

    config, backup_path = backup_device_config(device_params, args.backup_dir)

    if not config:
        logger.error("Backup failed")
        sys.exit(1)

    if args.show_diff:
        hostname = args.host.replace('.', '_')
        previous = get_previous_backup(args.backup_dir, hostname)
        diff = generate_config_diff(previous, config, args.host)

        if diff:
            print("\n--- Configuration Differences ---")
            print(diff)

    logger.info("Backup completed successfully")


if __name__ == "__main__":
    main()
```