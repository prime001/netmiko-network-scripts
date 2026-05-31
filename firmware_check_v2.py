```python
#!/usr/bin/env python3
"""
Device Configuration Snapshot and Change Detection Tool

Purpose:
    Takes timestamped snapshots of network device running configurations
    and detects changes between consecutive runs. Useful for tracking
    configuration drift and detecting unauthorized modifications.

Usage:
    python config_snapshot.py --host 192.168.1.1 --username admin --device-type cisco_ios
    python config_snapshot.py --host 192.168.1.1 --username admin --device-type cisco_ios --compare --diff

Prerequisites:
    - netmiko installed (pip install netmiko)
    - Network device accessible via SSH/Telnet
    - User credentials with privilege to view running configuration
    - Device must support 'show running-config' or equivalent command

Output:
    - Configuration snapshots stored in ./snapshots/ directory with timestamps
    - Change summaries printed to console
    - Detailed unified diffs available with --diff flag
    - Logging output to config_snapshot.log
"""

import argparse
import getpass
import logging
import sys
from datetime import datetime
from difflib import unified_diff
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


def setup_logging(log_level):
    """Configure logging to file and console."""
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('config_snapshot.log')
        ]
    )
    return logging.getLogger(__name__)


def create_snapshot_dir():
    """Create snapshots directory if it doesn't exist."""
    snapshot_dir = Path('snapshots')
    snapshot_dir.mkdir(exist_ok=True)
    return snapshot_dir


def connect_device(device_params, logger):
    """Establish SSH/Telnet connection to network device."""
    try:
        logger.info(f"Connecting to {device_params['host']}")
        connection = ConnectHandler(**device_params)
        logger.debug(f"Successfully connected to {device_params['host']}")
        return connection
    except NetmikoAuthenticationException as e:
        logger.error(f"Authentication failed for {device_params['host']}: {e}")
        sys.exit(1)
    except NetmikoTimeoutException as e:
        logger.error(f"Connection timeout to {device_params['host']}: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Connection error: {e}")
        sys.exit(1)


def get_hostname(connection, logger):
    """Extract hostname from device running configuration."""
    try:
        output = connection.send_command('show run | include hostname')
        if output:
            return output.split()[-1]
        return 'unknown-device'
    except Exception as e:
        logger.warning(f"Could not determine hostname: {e}")
        return 'unknown-device'


def get_config(connection, logger):
    """Retrieve running configuration from device."""
    try:
        logger.debug("Retrieving running configuration")
        config = connection.send_command('show running-config')
        logger.info("Configuration retrieved successfully")
        return config
    except Exception as e:
        logger.error(f"Failed to retrieve configuration: {e}")
        sys.exit(1)


def save_snapshot(config, hostname, snapshot_dir, logger):
    """Save configuration snapshot with timestamp."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = snapshot_dir / f"{hostname}_{timestamp}.txt"
    
    try:
        with open(filename, 'w') as f:
            f.write(config)
        logger.info(f"Snapshot saved to {filename}")
        return filename
    except IOError as e:
        logger.error(f"Failed to write snapshot: {e}")
        sys.exit(1)


def find_previous_snapshot(snapshot_dir, hostname):
    """Locate most recent previous snapshot for device."""
    snapshots = sorted(
        snapshot_dir.glob(f"{hostname}_*.txt"),
        key=lambda x: x.stat().st_mtime,
        reverse=True
    )
    return snapshots[1] if len(snapshots) > 1 else None


def compare_configs(current_config, previous_file, hostname, logger):
    """Generate unified diff between current and previous configurations."""
    try:
        with open(previous_file, 'r') as f:
            previous_config = f.read()
        
        current_lines = current_config.splitlines(keepends=True)
        previous_lines = previous_config.splitlines(keepends=True)
        
        diff = list(unified_diff(
            previous_lines,
            current_lines,
            fromfile=f'{hostname}_previous',
            tofile=f'{hostname}_current'
        ))
        
        return diff if diff else None
    except IOError as e:
        logger.error(f"Failed to read previous snapshot: {e}")
        return None


def print_summary(diff):
    """Print change summary statistics."""
    additions = sum(1 for line in diff if line.startswith('+') and not line.startswith('+++'))
    deletions = sum(1 for line in diff if line.startswith('-') and not line.startswith('---'))
    
    print("\n=== Configuration Changes Detected ===")
    print(f"Lines added:    {additions}")
    print(f"Lines removed:  {deletions}")
    print(f"Total changes:  {len([l for l in diff if l[0] in '+-' and l[1] not in '+-'])}")


def main():
    parser = argparse.ArgumentParser(
        description='Snapshot device configurations and detect changes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument('--host', required=True, help='Device IP address or hostname')
    parser.add_argument('--username', required=True, help='SSH username')
    parser.add_argument('--password', help='SSH password (will prompt if not provided)')
    parser.add_argument('--device-type', default='cisco_ios', help='Netmiko device type')
    parser.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument('--timeout', type=int, default=10, help='Connection timeout in seconds')
    parser.add_argument('--compare', action='store_true', help='Compare with previous snapshot')
    parser.add_argument('--diff', action='store_true', help='Show detailed unified diff output')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help='Logging level (default: INFO)')
    
    args = parser.parse_args()
    logger = setup_logging(args.log_level)
    
    if not args.password:
        args.password = getpass.getpass('Password: ')
    
    device_params = {
        'device_type': args.device_type,
        'host': args.host,
        'username': args.username,
        'password': args.password,
        'port': args.port,
        'timeout': args.timeout,
    }
    
    snapshot_dir = create_snapshot_dir()
    connection = connect_device(device_params, logger)
    hostname = get_hostname(connection, logger)
    config = get_config(connection, logger)
    connection.disconnect()
    
    snapshot_file = save_snapshot(config, hostname, snapshot_dir, logger)
    
    if args.compare:
        previous = find_previous_snapshot(snapshot_dir, hostname)
        if previous:
            diff = compare_configs(config, previous, hostname, logger)
            if diff:
                print_summary(diff)
                if args.diff:
                    print("\n=== Detailed Unified Diff ===")
                    print(''.join(diff))
            else:
                print(f"\nNo configuration changes detected since {previous.name}")
        else:
            logger.info("No previous snapshot available for comparison")


if __name__ == '__main__':
    main()
```