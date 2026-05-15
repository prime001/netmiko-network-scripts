I'll proceed with the most portfolio-worthy option. Here are the three approaches with trade-offs:

---

**Approach 1 (Recommended): CDP/LLDP Neighbor Discovery**
Walks one or more seed devices and maps their CDP/LLDP neighbors — hostname, local interface, remote interface, platform, and IP. Optional recursive crawl to build a multi-hop topology. This is distinct from basic device inventory, showcases real network-layer knowledge, and is immediately practical.

**Approach 2: ARP + MAC Table Collector**
Pulls ARP and MAC address tables to resolve IP → MAC → switchport. Useful for host location. Simpler logic but heavily overlaps with what `device_discovery_v2.py` likely does (interface/IP inventory).

**Approach 3: VLAN Inventory**
Discovers VLANs and port assignments. Narrower scope, less distinct as a standalone discovery tool.

I'm going with **Approach 1 — CDP/LLDP Neighbor Discovery** (`cdp_lldp_neighbor_map.py`):

- **Input:** one seed device (host, credentials, device_type via argparse) + optional `--depth` for recursive hops
- **Logic:** connect → `show cdp neighbors detail` (or `show lldp neighbors detail`) → parse hostname, local intf, remote intf, platform, management IP → optionally recurse into each neighbor
- **Output:** tabular summary to stdout + optional JSON file (`--output`)
- **Error handling:** per-device `NetmikoTimeoutException` / `NetmikoAuthenticationException` caught and logged, script continues to remaining neighbors
- **Logging:** `logging` module, `--verbose` flag for DEBUG level
- **~120–150 lines**, PEP 8, module docstring, argparse, `if __name__ == "__main__"`

Does this design look right, or should I adjust the approach or scope?