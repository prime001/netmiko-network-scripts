```python
"""
Configuration Backup Utility

Backs up running configurations from network devices with timestamps.
Supports multiple device vendors via netmiko.

Usage:
    python config_backup.py -d 192.168.1.1 -u admin -p password123 -t cisco_ios
    python config_backup.py -f devices.txt -u admin -p password123

Prerequisites:
    - netmiko: pip install netmiko
    - Network connectivity to devices
    - Valid credentials with read access
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('config_backup.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


def create_backup_dir():
    """Create backups directory."""
    backup_dir = Path('backups')
    backup_dir.mkdir(exist_ok=True)
    return backup_dir


def backup_device(host, username, password, device_type, port=22, timeout=30):
    """Retrieve running configuration from device."""
    try:
        logger.info(f"Connecting to {host}...")
        device = {
            'device_type': device_type,
            'host': host,
            'username': username,
            'password': password,
            'port': port,
            'timeout': timeout,
        }

        with ConnectHandler(**device) as net_connect:
            if device_type in ['cisco_ios', 'cisco_xe', 'arista_eos']:
                config = net_connect.send_command('show running-config')
            elif device_type in ['juniper_junos', 'juniper_evo']:
                config = net_connect.send_command('show configuration')
            else:
                config = net_connect.send_command('show running-config')

            logger.info(f"Retrieved config from {host}")
            return config

    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        logger.error(f"Connection error for {host}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error retrieving config from {host}: {e}")
        return None


def save_config(backup_dir, host, config, device_type):
    """Save configuration to timestamped file."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = backup_dir / f"{host}_{device_type}_{timestamp}.cfg"

    try:
        with open(filename, 'w') as f:
            f.write(config)
        logger.info(f"Backup saved: {filename}")
        return True
    except IOError as e:
        logger.error(f"Failed to save backup: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description='Backup network device configurations')
    parser.add_argument('-d', '--device', help='Device IP/hostname')
    parser.add_argument('-f', '--file', help='File with device list (one per line)')
    parser.add_argument('-u', '--username', required=True, help='Username')
    parser.add_argument('-p', '--password', required=True, help='Password')
    parser.add_argument('-t', '--device-type', default='cisco_ios', help='Device type')
    parser.add_argument('--port', type=int, default=22, help='SSH port')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout in seconds')

    args = parser.parse_args()

    if not args.device and not args.file:
        parser.error('Specify --device or --file')

    backup_dir = create_backup_dir()
    devices = []

    if args.device:
        devices.append(args.device)
    else:
        try:
            with open(args.file) as f:
                devices = [line.strip() for line in f if line.strip()]
        except IOError as e:
            logger.error(f"Failed to read device file: {e}")
            sys.exit(1)

    if not devices:
        logger.error("No devices specified")
        sys.exit(1)

    successful, failed = 0, 0

    for device in devices:
        config = backup_device(device, args.username, args.password,
                              args.device_type, args.port, args.timeout)
        if config:
            if save_config(backup_dir, device, config, args.device_type):
                successful += 1
            else:
                failed += 1
        else:
            failed += 1

    logger.info(f"Backup complete: {successful} successful, {failed} failed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == '__main__':
    main()
```