```python
"""
Configuration Backup and Diff Tool

Purpose:
    Backs up running configurations and compares against previous versions
    to identify configuration changes. Useful for change tracking, compliance
    audits, and change management workflows.

Usage:
    python config_backup_diff.py --host 192.168.1.1 --device-type cisco_ios \\
        --username admin --password secret --backup-dir ./backups

    python config_backup_diff.py --host 192.168.1.1 --device-type cisco_ios \\
        --username admin --password secret --backup-dir ./backups --show-diff

Prerequisites:
    - netmiko installed (pip install netmiko)
    - Network connectivity to target device
    - Valid device credentials
    - Backup directory (created if needed)
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path
from difflib import unified_diff

from netmiko import ConnectHandler, NetmikoAuthenticationException, NetmikoTimeoutException


def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s'
    )
    return logging.getLogger(__name__)


def connect_device(device_params):
    """Establish connection to network device."""
    logger = logging.getLogger(__name__)
    try:
        logger.info(f"Connecting to {device_params['host']}")
        conn = ConnectHandler(**device_params)
        logger.debug(f"Successfully connected. Prompt: {conn.find_prompt()}")
        return conn
    except NetmikoAuthenticationException as e:
        logger.error(f"Authentication failed: {e}")
        sys.exit(1)
    except NetmikoTimeoutException as e:
        logger.error(f"Connection timeout: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Connection error: {e}")
        sys.exit(1)


def backup_config(conn, host, backup_dir):
    """Backup running configuration."""
    logger = logging.getLogger(__name__)

    try:
        logger.info("Retrieving running configuration")
        config = conn.send_command('show running-config')

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_host = host.replace('.', '_')
        backup_path = Path(backup_dir) / f"{safe_host}_{timestamp}.cfg"

        Path(backup_dir).mkdir(parents=True, exist_ok=True)
        backup_path.write_text(config)

        logger.info(f"Configuration backed up to {backup_path}")
        return backup_path, config

    except Exception as e:
        logger.error(f"Backup failed: {e}")
        sys.exit(1)


def get_previous_backup(backup_dir, safe_host):
    """Find the most recent previous backup."""
    backups = sorted(Path(backup_dir).glob(f"{safe_host}_*.cfg"))
    return backups[-2] if len(backups) >= 2 else None


def show_diff(current_config, previous_path):
    """Display differences between configs."""
    logger = logging.getLogger(__name__)
    previous_config = previous_path.read_text()

    diff_lines = list(unified_diff(
        previous_config.splitlines(keepends=True),
        current_config.splitlines(keepends=True),
        fromfile=f"Previous ({previous_path.name})",
        tofile="Current",
        lineterm=''
    ))

    if diff_lines:
        logger.info("Configuration changes detected:")
        print(''.join(diff_lines))
    else:
        logger.info("No configuration changes")


def main():
    parser = argparse.ArgumentParser(
        description='Backup and compare device configurations'
    )
    parser.add_argument('--host', required=True, help='Device IP or hostname')
    parser.add_argument('--device-type', required=True,
                       help='Device type (cisco_ios, arista_eos, etc.)')
    parser.add_argument('--username', required=True, help='Device username')
    parser.add_argument('--password', required=True, help='Device password')
    parser.add_argument('--port', type=int, default=22, help='SSH port')
    parser.add_argument('--backup-dir', default='./backups',
                       help='Backup directory path')
    parser.add_argument('--show-diff', action='store_true',
                       help='Show diff with previous backup')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable debug logging')

    args = parser.parse_args()
    logger = setup_logging(args.verbose)

    device_params = {
        'device_type': args.device_type,
        'host': args.host,
        'username': args.username,
        'password': args.password,
        'port': args.port,
    }

    conn = connect_device(device_params)
    try:
        safe_host = args.host.replace('.', '_')
        backup_path, config = backup_config(conn, args.host, args.backup_dir)

        if args.show_diff:
            previous = get_previous_backup(args.backup_dir, safe_host)
            if previous:
                show_diff(config, previous)
            else:
                logger.info("No previous backup available for comparison")
    finally:
        conn.disconnect()
        logger.debug("Connection closed")


if __name__ == '__main__':
    main()
```