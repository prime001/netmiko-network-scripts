```python
#!/usr/bin/env python3
"""
Configuration Drift Detector

Purpose:
    Detects configuration drift between running and startup configurations
    on network devices. Helps identify unauthorized changes or sync issues.

Usage:
    python config_drift_detector.py --host 10.0.0.1 --device-type cisco_ios \
        --username admin --password secret [--save-diff]

Prerequisites:
    - netmiko installed (pip install netmiko)
    - Device SSH credentials
    - SSH connectivity to device
    - Device must support 'show running-config' and 'show startup-config'

Output:
    - Detects configuration drift
    - Shows diffs if present
    - Can save detailed diff to file
"""

import argparse
import logging
import sys
import difflib
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, AuthenticationException

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def get_configs(device_dict):
    """Retrieve running and startup configurations from device."""
    try:
        with ConnectHandler(**device_dict) as device:
            logger.info(f"Connected to {device_dict['host']}")
            
            running = device.send_command('show running-config')
            logger.info("Retrieved running-config")
            
            startup = device.send_command('show startup-config')
            logger.info("Retrieved startup-config")
            
    except AuthenticationException as e:
        logger.error(f"Authentication failed: {e}")
        sys.exit(1)
    except NetmikoTimeoutException as e:
        logger.error(f"Connection timeout: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error retrieving configs: {e}")
        sys.exit(1)
    
    return running, startup


def detect_drift(running, startup):
    """Detect configuration differences between running and startup."""
    running_lines = running.split('\n')
    startup_lines = startup.split('\n')
    
    drift_detected = running_lines != startup_lines
    
    if drift_detected:
        diff = difflib.unified_diff(
            startup_lines,
            running_lines,
            fromfile='startup-config',
            tofile='running-config',
            lineterm=''
        )
        return True, list(diff)
    
    return False, []


def display_results(drift_detected, diff_lines, save_diff):
    """Display drift detection results."""
    print('\n' + '='*70)
    print('CONFIGURATION DRIFT DETECTION REPORT')
    print('='*70)
    
    if drift_detected:
        logger.warning("DRIFT DETECTED: Configurations do not match!")
        print("\n[WARNING] Running config differs from startup config\n")
        
        if diff_lines:
            print("Configuration differences (+ running, - startup):")
            print('-'*70)
            for line in diff_lines[:100]:
                print(line)
            if len(diff_lines) > 100:
                print(f"\n... and {len(diff_lines) - 100} more lines")
            print('-'*70)
        
        if save_diff:
            filename = f"config_drift_{save_diff}.diff"
            try:
                with open(filename, 'w') as f:
                    f.write('\n'.join(diff_lines))
                logger.info(f"Diff saved to {filename}")
                print(f"\nDetailed diff saved to: {filename}")
            except IOError as e:
                logger.error(f"Failed to save diff: {e}")
    else:
        logger.info("No drift detected - configs are synchronized")
        print("\n[OK] Running and startup configurations are identical")
    
    print('\n' + '='*70 + '\n')


def main():
    parser = argparse.ArgumentParser(
        description='Detect configuration drift on network devices'
    )
    parser.add_argument('--host', required=True, help='Device IP or hostname')
    parser.add_argument('--device-type', required=True, help='Device type for netmiko')
    parser.add_argument('--username', required=True, help='SSH username')
    parser.add_argument('--password', required=True, help='SSH password')
    parser.add_argument('--port', type=int, default=22, help='SSH port (default: 22)')
    parser.add_argument('--timeout', type=int, default=30,
                        help='Connection timeout in seconds (default: 30)')
    parser.add_argument('--save-diff', help='Save diff to file (filename prefix)')
    
    args = parser.parse_args()
    
    device_dict = {
        'device_type': args.device_type,
        'host': args.host,
        'username': args.username,
        'password': args.password,
        'port': args.port,
        'timeout': args.timeout,
    }
    
    logger.info(f"Checking config drift on {args.host}")
    running, startup = get_configs(device_dict)
    drift_detected, diff_lines = detect_drift(running, startup)
    display_results(drift_detected, diff_lines, args.save_diff)
    
    sys.exit(1 if drift_detected else 0)


if __name__ == '__main__':
    main()
```