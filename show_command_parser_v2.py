```python
#!/usr/bin/env python3
"""
Network Device Configuration Backup Tool

Purpose:
    Backup running configurations from network devices to timestamped files.
    Supports multiple vendors (Cisco IOS, IOS-XE, IOS-XR, Junos, Arista, etc.)

Usage:
    Single device:
        python config_backup.py --host 10.0.0.1 --username admin --password secret --device_type cisco_ios

    Multiple devices from file:
        python config_backup.py --devices devices.txt --username admin --password secret --output_dir ./backups

    Devices file format (one per line):
        hostname,device_type
        10.0.0.1,cisco_ios
        10.0.0.2,cisco_iosxe

Prerequisites:
    - netmiko library: pip install netmiko
    - Network connectivity to target devices
    - Valid SSH credentials
    - SSH enabled on target devices
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException


def setup_logging(verbose=False):
    """Configure logging with timestamps and levels."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger(__name__)


def backup_device(host, device_type, username, password, output_dir, 
                  port=22, timeout=30):
    """
    Backup configuration from a single device.
    
    Args:
        host: Device hostname/IP
        device_type: Device type (cisco_ios, junos, arista_eos, etc.)
        username: SSH username
        password: SSH password
        output_dir: Directory to store backups
        port: SSH port (default 22)
        timeout: Connection timeout in seconds
        
    Returns:
        True if successful, False otherwise
    """
    logger = logging.getLogger(__name__)
    device = None
    
    try:
        logger.info(f"Connecting to {host} ({device_type})...")
        
        device = ConnectHandler(
            host=host,
            device_type=device_type,
            username=username,
            password=password,
            port=port,
            timeout=timeout,
            global_delay_factor=1
        )
        
        device_name = host.replace(".", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{device_name}_{timestamp}.txt"
        filepath = Path(output_dir) / filename
        
        if device_type.startswith('cisco'):
            config = device.send_command("show running-config")
        elif device_type == 'junos':
            config = device.send_command("show configuration | display set")
        elif device_type == 'arista_eos':
            config = device.send_command("show running-config")
        else:
            config = device.send_command("show running-config")
        
        filepath.write_text(config)
        logger.info(f"Backup saved: {filepath} ({len(config)} bytes)")
        return True
        
    except NetmikoTimeoutException:
        logger.error(f"Timeout connecting to {host}")
        return False
    except NetmikoAuthenticationException:
        logger.error(f"Authentication failed for {host}")
        return False
    except Exception as e:
        logger.error(f"Error backing up {host}: {str(e)}")
        return False
    finally:
        if device:
            try:
                device.disconnect()
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(
        description="Backup network device configurations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python config_backup.py --host 10.0.0.1 --username admin --password secret"
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--host', help='Single device IP/hostname')
    group.add_argument('--devices', help='File with device list (hostname,device_type)')
    
    parser.add_argument('-u', '--username', required=True, help='SSH username')
    parser.add_argument('-p', '--password', required=True, help='SSH password')
    parser.add_argument('-t', '--device_type', default='cisco_ios', 
                       help='Device type (default: cisco_ios)')
    parser.add_argument('-o', '--output_dir', default='./backups',
                       help='Output directory for backups (default: ./backups)')
    parser.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument('--timeout', type=int, default=30, help='Connection timeout (default: 30s)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    logger = setup_logging(args.verbose)
    
    output_path = Path(args.output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    logger.info(f"Using output directory: {output_path.absolute()}")
    
    success_count = 0
    failure_count = 0
    
    if args.host:
        if backup_device(
            args.host, args.device_type, args.username, 
            args.password, args.output_dir, args.port, args.timeout
        ):
            success_count += 1
        else:
            failure_count += 1
    
    elif args.devices:
        try:
            with open(args.devices, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split(',')
                    if len(parts) < 2:
                        logger.warning(f"Invalid line format: {line}")
                        continue
                    
                    host, device_type = parts[0].strip(), parts[1].strip()
                    
                    if backup_device(
                        host, device_type, args.username,
                        args.password, args.output_dir, args.port, args.timeout
                    ):
                        success_count += 1
                    else:
                        failure_count += 1
                        
        except FileNotFoundError:
            logger.error(f"Device file not found: {args.devices}")
            sys.exit(1)
    
    logger.info(f"Backup complete: {success_count} succeeded, {failure_count} failed")
    sys.exit(0 if failure_count == 0 else 1)


if __name__ == "__main__":
    main()
```