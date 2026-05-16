```python
#!/usr/bin/env python3
"""
Device Configuration Archiver

Backs up running configurations from network devices to local storage with
timestamps and optional Git version control integration.

Prerequisites:
  - netmiko installed: pip install netmiko
  - Network device credentials (SSH)
  - Optional: Git repository for backups

Usage:
  python config_archiver.py --host 192.168.1.1 --device-type cisco_ios \
    --username admin --password mypassword --backup-dir ./backups

  python config_archiver.py --host 192.168.1.1 --device-type arista_eos \
    --username admin --backup-dir ./backups --git-commit
"""

import argparse
import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException


def setup_logging(log_level=logging.INFO):
    """Configure logging for the script."""
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)


def backup_device_config(device_params, backup_dir):
    """
    Connect to device and backup running configuration.
    
    Args:
        device_params: Dictionary with connection parameters
        backup_dir: Path to backup directory
        
    Returns:
        Path to backup file or None on failure
    """
    logger = logging.getLogger(__name__)
    
    try:
        logger.info(f"Connecting to {device_params['host']}")
        device = ConnectHandler(**device_params)
        logger.info("Successfully connected")
        
        logger.info("Retrieving running configuration")
        config = device.send_command("show running-config")
        device.disconnect()
        
        backup_dir = Path(backup_dir)
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        hostname = device_params['host'].replace('.', '_')
        backup_file = backup_dir / f"{hostname}_{timestamp}_running-config.txt"
        
        backup_file.write_text(config)
        logger.info(f"Configuration backed up to {backup_file}")
        
        return backup_file
        
    except NetmikoAuthenticationException as e:
        logger.error(f"Authentication failed: {e}")
        return None
    except NetmikoTimeoutException as e:
        logger.error(f"Connection timeout: {e}")
        return None
    except Exception as e:
        logger.error(f"Error during backup: {e}")
        return None


def git_commit_backup(backup_file, backup_dir):
    """
    Commit backup file to Git repository.
    
    Args:
        backup_file: Path to the backup file
        backup_dir: Base backup directory path
    """
    logger = logging.getLogger(__name__)
    
    try:
        backup_dir = Path(backup_dir)
        
        if not (backup_dir / ".git").exists():
            logger.info("Initializing git repository")
            subprocess.run(
                ["git", "init"],
                cwd=backup_dir,
                check=True,
                capture_output=True
            )
        
        subprocess.run(
            ["git", "add", backup_file.name],
            cwd=backup_dir,
            check=True,
            capture_output=True
        )
        
        commit_msg = f"Backup: {backup_file.name}"
        subprocess.run(
            ["git", "commit", "-m", commit_msg],
            cwd=backup_dir,
            check=True,
            capture_output=True
        )
        
        logger.info(f"Committed backup to git: {commit_msg}")
        
    except subprocess.CalledProcessError as e:
        logger.warning(f"Git commit failed: {e.stderr.decode()}")
    except FileNotFoundError:
        logger.warning("Git not installed or not in PATH")
    except Exception as e:
        logger.warning(f"Error committing to git: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Backup network device configurations to local storage"
    )
    parser.add_argument(
        "--host",
        required=True,
        help="Target device IP or hostname"
    )
    parser.add_argument(
        "--device-type",
        required=True,
        help="Device type (e.g., cisco_ios, arista_eos, juniper_junos)"
    )
    parser.add_argument(
        "--username",
        required=True,
        help="SSH username"
    )
    parser.add_argument(
        "--password",
        help="SSH password (or use environment variable NETMIKO_PASSWORD)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=22,
        help="SSH port (default: 22)"
    )
    parser.add_argument(
        "--backup-dir",
        default="./backups",
        help="Directory to store backups (default: ./backups)"
    )
    parser.add_argument(
        "--git-commit",
        action="store_true",
        help="Commit backup to git repository"
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level"
    )
    
    args = parser.parse_args()
    
    setup_logging(getattr(logging, args.log_level))
    logger = logging.getLogger(__name__)
    
    password = args.password or os.environ.get("NETMIKO_PASSWORD")
    if not password:
        logger.error("Password not provided. Set --password or NETMIKO_PASSWORD")
        return 1
    
    device_params = {
        "device_type": args.device_type,
        "host": args.host,
        "username": args.username,
        "password": password,
        "port": args.port,
    }
    
    backup_file = backup_device_config(device_params, args.backup_dir)
    
    if backup_file:
        if args.git_commit:
            git_commit_backup(backup_file, args.backup_dir)
        return 0
    else:
        return 1


if __name__ == "__main__":
    exit(main())
```