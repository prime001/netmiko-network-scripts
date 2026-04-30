#!/usr/bin/env python3
"""
Configuration Backup and Drift Detection Tool

Purpose:
    Backup running configuration from network devices and compare against
    startup configuration to detect unintended changes. Supports multiple
    vendors (Cisco IOS/IOS-XE, Arista, Juniper, etc.).

Usage:
    python 008_config_backup_diff.py -d 192.168.1.1 -u admin -p password --backup
    python 008_config_backup_diff.py -d 192.168.1.1 -u admin -p password --diff
    python 008_config_backup_diff.py -d 192.168.1.1 -u admin -p password --device-type ios

Prerequisites:
    - netmiko >= 4.0.0
    - Python >= 3.8
    - Network device IP/hostname reachable
    - SSH enabled on target device
    - User credentials with read access to configuration

Output:
    - Backup files: config_backups/{hostname}_{timestamp}.txt
    - Diff report: stdout
    - Log file: config_backup.log
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path
from difflib import unified_diff

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException


def setup_logging(log_file="config_backup.log"):
    """Configure logging to file and console."""
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    
    return logger


def connect_device(device_dict, logger):
    """Connect to network device with error handling."""
    try:
        logger.info(f"Connecting to {device_dict['host']}...")
        device = ConnectHandler(**device_dict)
        logger.info(f"Successfully connected to {device_dict['host']}")
        return device
    except NetmikoTimeoutException:
        logger.error(f"Timeout connecting to {device_dict['host']}")
        sys.exit(1)
    except NetmikoAuthenticationException:
        logger.error(f"Authentication failed for {device_dict['host']}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error connecting to device: {e}")
        sys.exit(1)


def get_running_config(device, logger):
    """Retrieve running configuration."""
    try:
        logger.debug("Retrieving running configuration...")
        config = device.send_command("show running-config", use_textfsm=False)
        logger.debug(f"Retrieved {len(config)} bytes of running config")
        return config
    except Exception as e:
        logger.error(f"Failed to retrieve running config: {e}")
        raise


def get_startup_config(device, logger):
    """Retrieve startup configuration."""
    try:
        logger.debug("Retrieving startup configuration...")
        config = device.send_command("show startup-config", use_textfsm=False)
        logger.debug(f"Retrieved {len(config)} bytes of startup config")
        return config
    except Exception as e:
        logger.error(f"Failed to retrieve startup config: {e}")
        raise


def backup_config(running_config, device_name, logger):
    """Save configuration to backup file."""
    backup_dir = Path("config_backups")
    backup_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = backup_dir / f"{device_name}_{timestamp}.txt"
    
    try:
        filename.write_text(running_config)
        logger.info(f"Configuration backed up to {filename}")
        return filename
    except IOError as e:
        logger.error(f"Failed to write backup file: {e}")
        raise


def compare_configs(running, startup, hostname, logger):
    """Compare running vs startup configuration and display differences."""
    running_lines = running.splitlines(keepends=True)
    startup_lines = startup.splitlines(keepends=True)
    
    diff = unified_diff(
        startup_lines,
        running_lines,
        fromfile=f"{hostname} (startup)",
        tofile=f"{hostname} (running)",
        lineterm=""
    )
    
    diff_output = list(diff)
    
    if diff_output:
        logger.warning(f"Configuration differences detected on {hostname}")
        print("\n" + "=" * 70)
        print(f"Configuration Diff for {hostname}")
        print("=" * 70)
        for line in diff_output:
            print(line.rstrip())
        print("=" * 70 + "\n")
        return True
    else:
        logger.info(f"No configuration differences on {hostname}")
        print(f"\n✓ {hostname}: Running and startup configs match\n")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Backup and compare network device configurations"
    )
    parser.add_argument(
        "-d", "--device",
        required=True,
        help="Device IP address or hostname"
    )
    parser.add_argument(
        "-u", "--username",
        required=True,
        help="SSH username"
    )
    parser.add_argument(
        "-p", "--password",
        required=True,
        help="SSH password"
    )
    parser.add_argument(
        "--device-type",
        default="cisco_ios",
        choices=["cisco_ios", "cisco_iosxe", "arista_eos", "juniper_junos"],
        help="Device type (default: cisco_ios)"
    )
    parser.add_argument(
        "--backup",
        action="store_true",
        help="Backup running configuration"
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Compare running vs startup config"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=22,
        help="SSH port (default: 22)"
    )
    
    args = parser.parse_args()
    
    logger = setup_logging()
    
    if not (args.backup or args.diff):
        logger.error("Must specify --backup and/or --diff")
        sys.exit(1)
    
    device_dict = {
        "device_type": args.device_type,
        "host": args.device,
        "username": args.username,
        "password": args.password,
        "port": args.port,
        "timeout": 30,
    }
    
    device = connect_device(device_dict, logger)
    
    try:
        hostname = device.send_command("show hostname", use_textfsm=False).strip()
        running_config = get_running_config(device, logger)
        
        if args.backup:
            backup_config(running_config, hostname, logger)
        
        if args.diff:
            startup_config = get_startup_config(device, logger)
            has_diff = compare_configs(running_config, startup_config, hostname, logger)
            if has_diff:
                sys.exit(2)
    
    except Exception as e:
        logger.error(f"Operation failed: {e}")
        sys.exit(1)
    finally:
        device.disconnect()
        logger.info("Disconnected from device")


if __name__ == "__main__":
    main()