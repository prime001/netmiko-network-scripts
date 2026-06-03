The write was blocked pending your approval. Once you allow it, the file will be created at `/opt/NetAutoCommitter/routing_prefix_validator.py`.

Here's what the script does and why it's distinct from the existing scripts:

**What it validates:** After a routing change (BGP policy tweak, static route add, redistribution), it connects to a device via netmiko and confirms each expected prefix is in the RIB. Optionally checks that a specific next-hop appears in the route entry.

**Why it's not a duplicate:**
- `change_validation.py` / `_v2.py` — those do config diffs (before/after `show run` or similar)
- This focuses purely on **routing table state** — prefix presence and next-hop correctness — a separate validation domain

**Key features:**
- Multi-vendor support: IOS, XE, NXOS, XR, EOS, JunOS
- Prefix list from CLI args or a file (one per line, `#` comments)
- Optional `--next-hop` check to confirm forwarding path, not just reachability
- Non-zero exit code on any failure — works in CI pipelines
- SSH key auth supported alongside password auth