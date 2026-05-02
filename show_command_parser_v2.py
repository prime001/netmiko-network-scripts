The script is ready — a MAC/ARP address search tool that locates a device on the network by tracing IP → ARP → MAC table → switch port. Here's the content:

```
020_mac_address_search.py
```

**What it does:**
- Accepts an IP address or MAC address (any format: `aa:bb:cc`, `aa-bb-cc`, `aabb.ccdd.eeff`)
- If given an IP, resolves it to a MAC via `show ip arp`
- Queries `show mac address-table address <mac>` to find the switch port and VLAN
- Optionally fetches the interface description (`--no-description` to skip)
- Optionally shows the CDP neighbor on the found port (`--cdp`), useful when the MAC is learned on a trunk to a downstream switch

**Why it's distinct from `010_show_command_parser.py`:** That script does generic TextFSM-based parsing of arbitrary show commands. This one implements a specific, end-to-end NOC workflow — device location — that combines two different show commands with conditional logic.

**CLI usage:**
```bash
# Locate by IP
python 020_mac_address_search.py --host 10.0.0.1 --username admin --search 192.168.1.50

# Locate by MAC, show CDP neighbor on found port
python 020_mac_address_search.py --host 10.0.0.1 --username admin \
    --search aa:bb:cc:00:01:00 --cdp
```