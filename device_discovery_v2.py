The file write needs your approval. Once granted, the script will be at `/opt/NetAutoCommitter/cdp_lldp_mapper.py`.

The script is a **CDP/LLDP topology crawler** — distinct from the existing discovery scripts (which scan subnets/ping sweep). This one:

- Connects to a **seed device** via SSH using netmiko
- Parses `show cdp neighbors detail` or `show lldp neighbors detail`
- **BFS-crawls** discovered neighbors up to `--depth` hops, recursively SSHing into each
- Prints a formatted table and optionally writes a JSON topology report
- Handles auth failures and timeouts gracefully, skipping unreachable devices

Key CLI arguments: `--host`, `--username`, `--password`, `--protocol cdp|lldp`, `--depth N`, `--output file.json`.