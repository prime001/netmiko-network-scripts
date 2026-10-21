```python
"""
Configuration Backup Utility

Purpose:
    Backs up running configuration from network devices using netmiko.
    Supports multiple device types and saves timestamped backups to disk.

Usage:
    python config_backup.py --host 192.168.1.1 --device-type cisco_ios \
        --username admin --password secret
    
    python config_backup.py --file devices.csv --username admin --password secret

Prerequisites:
    - netmiko installed: pip install netmiko
    - Network connectivity to target devices
    - Appropriate credentials with read access
    - CSV file format (for --file): host,device_type,username,password
"""

import argparse
import csv
import logging
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.ssh_exception import (
    NetMikoTimeoutException,
    NetMikoAuthenticationException,
)


def setup_logging(verbose=False):
    """Configure logging with timestamped format."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=level,
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    return logging.getLogger(__name__)


def create_backup_directory():
    """Create timestamped backup directory."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = Path(f'backups_{timestamp}')
    backup_dir.mkdir(exist_ok=True)
    return backup_dir


def backup_device_config(device_params, backup_dir, logger):
    """
    Connect to device and backup running configuration.
    
    Args:
        device_params: Dictionary with device connection parameters
        backup_dir: Path object for backup directory
        logger: Logger instance
    
    Returns:
        Tuple of (success: bool, message: str, config_length: int)
    """
    host = device_params.get('host')
    device_type = device_params.get('device_type')
    
    try:
        logger.info(f'Connecting to {host} ({device_type})')
        device = ConnectHandler(**device_params)
        
        logger.debug('Retrieving running configuration')
        config = device.send_command('show running-config')
        device.disconnect()
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = backup_dir / f'{host}_{device_type}_{timestamp}.cfg'
        
        with open(filename, 'w') as f:
            f.write(config)
        
        config_length = len(config)
        msg = f'Successfully backed up {host} ({config_length} bytes)'
        logger.info(msg)
        return True, msg, config_length
        
    except NetMikoTimeoutException as e:
        msg = f'Connection timeout to {host}: {str(e)}'
        logger.error(msg)
        return False, msg, 0
    except NetMikoAuthenticationException as e:
        msg = f'Authentication failed for {host}: {str(e)}'
        logger.error(msg)
        return False, msg, 0
    except Exception as e:
        msg = f'Error backing up {host}: {type(e).__name__}: {str(e)}'
        logger.error(msg)
        return False, msg, 0


def load_devices_from_file(file_path, logger):
    """Load device parameters from CSV file."""
    devices = []
    required_fields = {'host', 'device_type', 'username', 'password'}
    
    try:
        with open(file_path, 'r') as f:
            reader = csv.DictReader(f)
            for row_num, row in enumerate(reader, start=2):
                if not all(k in row for k in required_fields):
                    logger.warning(
                        f'Row {row_num}: Missing required fields. '
                        f'Expected: {required_fields}'
                    )
                    continue
                devices.append(dict(row))
        
        logger.info(f'Loaded {len(devices)} devices from {file_path}')
        return devices
        
    except FileNotFoundError:
        logger.error(f'File not found: {file_path}')
        return []
    except Exception as e:
        logger.error(f'Error reading {file_path}: {str(e)}')
        return []


def main():
    parser = argparse.ArgumentParser(
        description='Backup network device running configurations'
    )
    
    parser.add_argument('--host', help='Target device hostname or IP')
    parser.add_argument(
        '--device-type',
        help='Netmiko device type (cisco_ios, arista_eos, juniper_junos, etc.)',
    )
    parser.add_argument('--username', required=True, help='SSH username')
    parser.add_argument('--password', required=True, help='SSH password')
    parser.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument(
        '--file', help='CSV file with devices (host, device_type, username, password)'
    )
    parser.add_argument(
        '--timeout', type=int, default=30, help='Connection timeout in seconds'
    )
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    logger = setup_logging(args.verbose)
    
    if not args.host and not args.file:
        parser.error('Either --host or --file must be specified')
    
    devices = []
    
    if args.file:
        devices = load_devices_from_file(args.file, logger)
    else:
        if not args.device_type:
            parser.error('--device-type required when using --host')
        devices = [
            {
                'host': args.host,
                'device_type': args.device_type,
                'username': args.username,
                'password': args.password,
                'port': args.port,
                'timeout': args.timeout,
            }
        ]
    
    if not devices:
        logger.error('No devices to process')
        return 1
    
    backup_dir = create_backup_directory()
    logger.info(f'Backups directory: {backup_dir}')
    
    results = {'success': 0, 'failed': 0, 'total_bytes': 0}
    
    for device in devices:
        device.setdefault('port', args.port)
        device.setdefault('timeout', args.timeout)
        
        success, message, config_length = backup_device_config(
            device, backup_dir, logger
        )
        if success:
            results['success'] += 1
            results['total_bytes'] += config_length
        else:
            results['failed'] += 1
    
    logger.info('=' * 70)
    logger.info(
        f"Summary: {results['success']} succeeded, {results['failed']} failed"
    )
    logger.info(f"Total backed up: {results['total_bytes']:,} bytes")
    logger.info('=' * 70)
    
    return 0 if results['failed'] == 0 else 1


if __name__ == '__main__':
    exit(main())
```