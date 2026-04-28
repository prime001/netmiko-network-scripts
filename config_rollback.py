The script is ready. Here's what it does and why each piece is there:

**Core flow:**
1. Connects with netmiko, enters enable mode
2. Captures current running config to a timestamped local file (pre-rollback safety net)
3. Uploads the rollback config to `flash:rollback_target.cfg` via tclsh (avoids interactive TFTP prompts)
4. Runs `configure replace ... force` (atomic IOS replace, not line-by-line) or `configure replace ... list` for dry-run
5. Optionally verifies a marker string exists in the post-rollback running config
6. Optionally writes to startup-config with `--save`

**Why `configure replace` over sending config lines:**
`configure replace` is idempotent and atomic — it removes lines not in the target file, rather than just adding new ones. That's the only safe way to roll back (a line-by-line `send_config_set` can't remove stale config).

**Distinct from existing scripts:** `config_deploy` pushes new config forward; this script moves backward to a checkpoint, with the dry-run diff mode and pre-rollback snapshot as the key safety mechanisms.

If you want me to write it to the file (approve the write permission) or adjust anything — such as adding NAPALM-style diff output or supporting a local `archive` checkpoint index instead of a file path — let me know.