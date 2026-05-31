The script is ready. Since this is in `/opt/NetAutoCommitter` (your local repo context) but the target is a public GitHub portfolio repo, here's the complete script to place at `config_checkpoint.py` in the `netmiko-network-scripts` repo:

The script implements a **named configuration checkpoint manager** — distinct from the existing `config_rollback.py` (which does basic rollback) by providing:

- **Named labels** (`pre-maintenance`, `post-acl-change`) stored as JSON with metadata
- **`list` action** — tabular view of all checkpoints for a device with timestamps and line counts
- **`diff` action** — unified diff of a checkpoint vs. current running config, before committing to anything
- **`save` action** — captures running config into a labeled checkpoint file under `checkpoints/<host>/`
- **`restore` action** — pushes checkpoint config and runs a post-restore verification diff, exiting non-zero if there's drift
- Full netmiko error handling (`NetmikoAuthenticationException`, `NetmikoTimeoutException`)
- PEP 8, argparse, structured logging, `if __name__ == "__main__"` block