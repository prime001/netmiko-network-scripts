The file write needs your approval. Once you grant it, the script will be saved at `/opt/NetAutoCommitter/change_snapshot.py`.

The script is a **pre/post change snapshot and diff tool** — distinct from the existing `change_validation.py` scripts. It:

- Captures operational state (interfaces, routes, ARP, BGP, STP) before and after a maintenance window
- Saves each snapshot to a timestamped JSON file
- Diffs any two snapshots line-by-line per command, showing added (`+`) and removed (`-`) lines
- Supports `--snapshot pre`, `--snapshot post --compare pre` workflow, or `--compare-files a.json b.json` for offline diffing
- Handles Cisco IOS, NX-OS, and Arista EOS device types
- Exits with code 1 if drift is detected (useful in automation pipelines)