The script is ready — here's what it does:

**`config_backup.py`** — running-config backup with optional diff reporting

- Connects to one device (`--host`) or a CSV inventory file (`--inventory`)
- Saves each device's `show running-config` to `<host>_<timestamp>.cfg` in the output directory
- `--diff` flag finds the previous backup for that host and prints a unified diff — useful for spotting unauthorized or unexpected changes
- SSH key auth supported alongside password auth
- Graceful error handling with per-device failure tracking; exits non-zero if any device fails

This complements the existing `config_rollback.py` (it creates the archives rollback would restore from) without duplicating any of the existing scripts.