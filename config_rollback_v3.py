I need your permission to write the file. Once approved, the script will be saved as `config_diff.py` — a running-config baseline comparator that:

- Fetches running config via netmiko (SSH)
- Diffs it against a saved baseline file (unified diff with color output)
- Can save the current config as a new baseline with `--save-baseline`
- Supports Cisco IOS/XE/NX-OS, Arista EOS, Juniper JunOS, and ASA
- Returns exit code 1 if drift is detected (useful for CI/alerting pipelines)

This fills a real gap — the existing scripts cover rollback (applying old config) and deploy (pushing new config), but nothing compares running state against a known-good snapshot for drift detection.