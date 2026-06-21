```python
#!/usr/bin/env python3
"""
Network Device Diagnostic Report Generator.

Collects diagnostic information from network devices and generates
timestamped reports including device version, uptime, CPU/memory usage,
interface summary, and routing information for documentation and troubleshooting.

Prerequisites:
    - netmiko >= 4.0.0
    - Device must be reachable via SSH (port 22 by default)
    - Network device must support standard show commands

Usage:
    python3 device_diagnostics.py -d 192.168.1.1 -t cisco_ios -u admin -p password
    python3 device_diagnostics.py -d core-router.example.com -t arista_eos -u admin
"""

import argparse
import json
import logging
from datetime import datetime
from pathlib import Path
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

VENDOR_COMMANDS = {
    'cisco_ios': {
        'version': 'show version',
        'interfaces': 'show interface summary',
        'routing': 'show ip route summary',
    },
    'cisco_iosxe': {
        'version': 'show version',
        'interfaces': 'show interface summary',
        'routing': 'show ip route summary',
    },
    'arista_eos': {
        'version': 'show version',
        'interfaces': 'show interface summary',
        'routing': 'show ip route summary',
    },
    'juniper_junos': {
        'version': 'show version',
        'interfaces': 'show interfaces summary',
        'routing': 'show route summary',
    },
}


def collect_diagnostics(device_params):
    """Collect diagnostic information from network device."""
    try:
        net_connect = ConnectHandler(**device_params)
        logger.info(f"Connected to {device_params['host']}")
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        logger.error(f"Connection failed to {device_params['host']}: {e}")
        return None

    diagnostics = {
        'timestamp': datetime.now().isoformat(),
        'host': device_params['host'],
        'device_type': device_params['device_type'],
    }

    device_type = device_params['device_type']
    if device_type not in VENDOR_COMMANDS:
        logger.error(f"Unsupported device type: {device_type}")
        net_connect.disconnect()
        return None

    try:
        for key, cmd in VENDOR_COMMANDS[device_type].items():
            try:
                output = net_connect.send_command(cmd)
                diagnostics[key] = output
                logger.info(f"Collected {key} from {device_params['host']}")
            except Exception as e:
                logger.warning(f"Failed to collect {key}: {e}")
                diagnostics[key] = f"Error: {str(e)}"
    finally:
        net_connect.disconnect()
        logger.info(f"Disconnected from {device_params['host']}")

    return diagnostics


def generate_report(diagnostics, output_dir):
    """Generate timestamped text and JSON reports."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = diagnostics['timestamp'].replace(':', '-').split('.')[0]
    host = diagnostics['host'].replace('.', '_')

    txt_file = output_path / f"{host}_diagnostics_{timestamp}.txt"
    with open(txt_file, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("NETWORK DEVICE DIAGNOSTIC REPORT\n")
        f.write("=" * 70 + "\n")
        f.write(f"Device: {diagnostics['host']}\n")
        f.write(f"Type: {diagnostics['device_type']}\n")
        f.write(f"Timestamp: {diagnostics['timestamp']}\n")
        f.write("=" * 70 + "\n")

        for key, value in diagnostics.items():
            if key not in ['timestamp', 'host', 'device_type']:
                f.write(f"\n{key.upper()}\n")
                f.write("-" * 70 + "\n")
                f.write(f"{value}\n")

    logger.info(f"Text report saved: {txt_file}")

    json_file = output_path / f"{host}_diagnostics_{timestamp}.json"
    with open(json_file, 'w') as f:
        json.dump(diagnostics, f, indent=2)

    logger.info(f"JSON report saved: {json_file}")
    return str(txt_file), str(json_file)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Generate network device diagnostic reports',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument('-d', '--device', required=True,
                        help='Device IP address or hostname')
    parser.add_argument('-t', '--type', required=True, dest='device_type',
                        help='Device type (cisco_ios, arista_eos, juniper_junos, etc.)')
    parser.add_argument('-u', '--username', required=True,
                        help='Username for device authentication')
    parser.add_argument('-p', '--password', help='Password (prompted if not provided)')
    parser.add_argument('-o', '--output', default='./reports',
                        help='Output directory for reports (default: ./reports)')
    parser.add_argument('--port', type=int, default=22,
                        help='SSH port (default: 22)')
    parser.add_argument('--timeout', type=int, default=30,
                        help='Connection timeout in seconds (default: 30)')

    args = parser.parse_args()

    import getpass
    password = args.password or getpass.getpass(f"Password for {args.username}: ")

    device_params = {
        'device_type': args.device_type,
        'host': args.device,
        'username': args.username,
        'password': password,
        'port': args.port,
        'timeout': args.timeout,
    }

    logger.info(f"Starting diagnostic collection for {args.device}")
    diagnostics = collect_diagnostics(device_params)

    if diagnostics:
        txt_file, json_file = generate_report(diagnostics, args.output)
        logger.info(f"Diagnostic collection completed successfully")
        logger.info(f"Reports: {txt_file} and {json_file}")
        return 0
    else:
        logger.error("Failed to collect diagnostics from device")
        return 1


if __name__ == '__main__':
    exit(main())
```