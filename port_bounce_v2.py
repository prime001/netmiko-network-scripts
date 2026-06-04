#!/usr/bin/env python3
"""
BGP Peer Status Monitor

Monitors BGP peer status, route counts, and uptime on Cisco/Arista devices.
Useful for circuit and peer health monitoring across production networks.

Usage:
    python bgp_monitor.py -d 192.168.1.1 -u admin -p password --device-type cisco_ios
    python bgp_monitor.py -d 10.0.0.5 -u netadmin -p mypass -v

Prerequisites:
    - netmiko installed (pip install netmiko)
    - Device must have BGP configured and enabled
    - SSH credentials must have read access to device
    - Device must be reachable via SSH (port 22 by default)

Output:
    Displays formatted BGP peer status table with address, ASN, state, and
    prefix count. Alerts on peers in non-established states.

"""

import argparse
import logging
import sys
import re
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


def configure_logging(verbose=False):
    """Configure logging for the script."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)


def connect_to_device(device_params, logger):
    """Establish SSH connection to network device."""
    try:
        logger.info(f"Connecting to {device_params['host']}")
        device = ConnectHandler(**device_params)
        logger.info("Connection established successfully")
        return device
    except NetmikoAuthenticationException as e:
        logger.error(f"Authentication failed: {e}")
        sys.exit(1)
    except NetmikoTimeoutException as e:
        logger.error(f"Connection timeout: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Connection failed: {e}")
        sys.exit(1)


def get_bgp_summary(device, logger):
    """Retrieve BGP summary information from device."""
    try:
        logger.debug("Sending 'show ip bgp summary' command")
        output = device.send_command('show ip bgp summary')
        logger.debug("BGP summary retrieved successfully")
        return output
    except Exception as e:
        logger.error(f"Failed to retrieve BGP summary: {e}")
        return ""


def parse_bgp_summary(output, logger):
    """Parse BGP summary output into structured peer data."""
    peers = []
    peer_section = False
    
    for line in output.split('\n'):
        line = line.strip()
        
        if not line or 'Neighbor' in line and 'V' in line:
            peer_section = True
            continue
        
        if not peer_section or not line:
            continue
        
        if re.match(r'^\d+\.\d+\.\d+\.\d+', line):
            parts = line.split()
            if len(parts) >= 6:
                peer = {
                    'address': parts[0],
                    'asn': parts[1],
                    'version': parts[2],
                    'msg_rcvd': parts[3],
                    'msg_sent': parts[4],
                    'tbl_ver': parts[5],
                    'inp_q': parts[6] if len(parts) > 6 else '0',
                    'out_q': parts[7] if len(parts) > 7 else '0',
                    'state': parts[8] if len(parts) > 8 else 'Unknown'
                }
                peers.append(peer)
                logger.debug(f"Parsed peer: {peer['address']} state: {peer['state']}")
    
    return peers


def analyze_bgp_peers(peers, logger):
    """Analyze BGP peer status and identify issues."""
    total_peers = len(peers)
    established = sum(1 for p in peers if p['state'].isdigit())
    down_peers = [p for p in peers if not p['state'].isdigit()]
    
    analysis = {
        'total': total_peers,
        'established': established,
        'down_peers': down_peers,
        'down_count': len(down_peers),
        'health_percentage': (established / total_peers * 100) if total_peers > 0 else 0
    }
    
    logger.info(f"BGP Analysis: {established}/{total_peers} peers established")
    
    return analysis


def generate_report(device_ip, peers, analysis, logger):
    """Generate formatted BGP status report."""
    print(f"\n{'='*80}")
    print(f"BGP Peer Status Monitor - {device_ip}")
    print(f"{'='*80}\n")
    
    print(f"Peer Statistics:")
    print(f"  Total Peers: {analysis['total']}")
    print(f"  Established: {analysis['established']}")
    print(f"  Down/Idle: {analysis['down_count']}")
    print(f"  Health: {analysis['health_percentage']:.1f}%\n")
    
    if peers:
        print(f"{'Neighbor':<18} {'ASN':<8} {'Msg Rcvd':<10} {'Msg Sent':<10} {'State':<15}")
        print(f"{'-'*80}")
        
        for peer in peers:
            state = peer['state']
            if state.isdigit():
                state_display = f"{state} prefixes"
            else:
                state_display = state
            
            print(f"{peer['address']:<18} {peer['asn']:<8} {peer['msg_rcvd']:<10} "
                  f"{peer['msg_sent']:<10} {state_display:<15}")
    
    if analysis['down_peers']:
        print(f"\n{'⚠️  ALERTS - Peers Not Established:':<80}")
        for peer in analysis['down_peers']:
            print(f"  {peer['address']:<18} ASN {peer['asn']:<8} State: {peer['state']}")
    else:
        print(f"\n{'✓ All peers established':<80}")
    
    print(f"\n{'='*80}\n")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description='Monitor BGP peer status and connectivity'
    )
    parser.add_argument('-d', '--device', required=True,
                        help='Target device IP address or hostname')
    parser.add_argument('-u', '--username', required=True,
                        help='SSH username for device authentication')
    parser.add_argument('-p', '--password', required=True,
                        help='SSH password for device authentication')
    parser.add_argument('-t', '--device-type', default='cisco_ios',
                        help='Device type for netmiko (default: cisco_ios)')
    parser.add_argument('--port', type=int, default=22,
                        help='SSH port (default: 22)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose debug logging')
    
    args = parser.parse_args()
    logger = configure_logging(args.verbose)
    
    device_params = {
        'device_type': args.device_type,
        'host': args.device,
        'username': args.username,
        'password': args.password,
        'port': args.port,
    }
    
    device = connect_to_device(device_params, logger)
    
    try:
        output = get_bgp_summary(device, logger)
        peers = parse_bgp_summary(output, logger)
        
        if not peers:
            logger.warning("No BGP peers found or BGP not configured")
            print("\n⚠️  No BGP peers detected on device.\n")
        else:
            analysis = analyze_bgp_peers(peers, logger)
            generate_report(args.device, peers, analysis, logger)
        
        logger.info("BGP monitoring complete")
    
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
    
    finally:
        try:
            device.disconnect()
            logger.debug("Device connection closed")
        except Exception as e:
            logger.warning(f"Error closing connection: {e}")


if __name__ == '__main__':
    main()