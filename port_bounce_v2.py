```python
#!/usr/bin/env python3
"""
Configuration Backup and Change Tracker

Backs up device running configuration to timestamped files and detects changes
between snapshots. Useful for compliance auditing and change management.

Usage:
    python config_backup_tracker.py --host 192.168.1.1 --device-type cisco_ios \
        --username admin --password secret --backup-dir ./backups

Prerequisites:
    - netmiko installed
    - Network device SSH/telnet access
    - Backup directory must exist or be creatable

Features:
    - Backs up running configuration with timestamp
    - Auto-detects device type if not specified
    - Compares with previous backup and shows changes
    - Generates historical backup files for audit trail
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path
from difflib import unified_diff

from netmiko import ConnectHandler
from netmiko.ssh_dispatcher import SSHDetect


def setup_logging(verbose=False):
    """Configure logging with appropriate level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=level
    )
    return logging.getLogger(__name__)


def detect_device_type(host, username, password, secret=None):
    """Auto-detect device type using netmiko's SSHDetect."""
    try:
        device = {
            'device_type': 'autodetect',
            'host': host,
            'username': username,
            'password': password,
            'secret': secret,
            'timeout': 10,
        }
        guesser = SSHDetect(**device)
        best_match = guesser.autodetect()
        return best_match
    except Exception as e:
        logging.error(f"Device type detection failed: {e}")
        return None


def backup_device_config(host, device_type, username, password, secret=None):
    """Connect to device and retrieve running configuration."""
    try:
        device = {
            'device_type': device_type,
            'host': host,
            'username': username,
            'password': password,
            'secret': secret,
            'timeout': 30,
        }

        logging.info(f"Connecting to {host} ({device_type})")
        net_connect = ConnectHandler(**device)

        config = net_connect.send_command('show running-config')
        net_connect.disconnect()

        logging.info(f"Successfully retrieved config from {host}")
        return config

    except Exception as e:
        logging.error(f"Failed to backup config from {host}: {e}")
        return None


def get_previous_backup(backup_dir, hostname):
    """Find the most recent previous backup for this host."""
    try:
        pattern = f"{hostname}_*.txt"
        backups = sorted(Path(backup_dir).glob(pattern))
        return backups[-1] if backups else None
    except Exception as e:
        logging.warning(f"Could not find previous backup: {e}")
        return None


def compare_configs(old_config, new_config):
    """Generate unified diff between old and new configurations."""
    old_lines = old_config.splitlines(keepends=True) if old_config else []
    new_lines = new_config.splitlines(keepends=True)

    diff = list(unified_diff(
        old_lines,
        new_lines,
        fromfile='Previous',
        tofile='Current',
        lineterm=''
    ))

    added = sum(1 for line in diff if line.startswith('+') and not line.startswith('+++'))
    removed = sum(1 for line in diff if line.startswith('-') and not line.startswith('---'))

    return ''.join(diff), added, removed


def save_backup(backup_dir, hostname, config):
    """Save configuration backup with timestamp."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{hostname}_{timestamp}.txt"
    filepath = Path(backup_dir) / filename

    try:
        filepath.write_text(config)
        logging.info(f"Backup saved to {filepath}")
        return filepath
    except Exception as e:
        logging.error(f"Failed to save backup: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description='Backup device configuration and track changes'
    )
    parser.add_argument('--host', required=True, help='Device IP address or hostname')
    parser.add_argument('--device-type', help='Device type (auto-detect if not specified)')
    parser.add_argument('--username', required=True, help='SSH username')
    parser.add_argument('--password', required=True, help='SSH password')
    parser.add_argument('--secret', help='Enable secret/password')
    parser.add_argument('--backup-dir', default='./backups', help='Backup directory')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--compare-only', action='store_true',
                       help='Only show comparison with previous backup')

    args = parser.parse_args()
    logger = setup_logging(args.verbose)

    try:
        Path(args.backup_dir).mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.error(f"Failed to create backup directory: {e}")
        sys.exit(1)

    device_type = args.device_type
    if not device_type:
        logger.info("Detecting device type...")
        device_type = detect_device_type(
            args.host, args.username, args.password, args.secret
        )
        if not device_type:
            sys.exit(1)
        logger.info(f"Detected device type: {device_type}")

    hostname = args.host.replace('.', '_')

    current_config = backup_device_config(
        args.host, device_type, args.username, args.password, args.secret
    )

    if not current_config:
        sys.exit(1)

    prev_backup_path = get_previous_backup(args.backup_dir, hostname)
    if prev_backup_path:
        logger.info(f"Found previous backup: {prev_backup_path.name}")
        previous_config = prev_backup_path.read_text()

        diff, added, removed = compare_configs(previous_config, current_config)
        if diff:
            logger.warning(f"Configuration changes detected: +{added} -{removed} lines")
            print("\n" + diff)
        else:
            logger.info("No configuration changes detected")

    if not args.compare_only:
        save_backup(args.backup_dir, hostname, current_config)

    logger.info("Backup operation completed successfully")


if __name__ == '__main__':
    main()
```