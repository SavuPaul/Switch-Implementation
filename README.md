## SWITCH_IMPLEMENTATION

The implementation is in the switch.py file.

### Task 1: MAC Table Formation
When sending data from one host to another, switches store the MAC address and the port of the switch through which the data came (excluding the broadcast address). If the destination is unknown, the switch floods the network with the data. The MAC table is used only when the destination host has been previously discovered.

To determine if an address is unicast, the `address_is_unicast` function checks whether the least significant bit of the first byte is:
- `0` → Unicast
- `1` → Not unicast (Multicast or Broadcast)

---

### Task 2: VLAN Handling
The switch configuration files are read for each switch, and the `vlan_ids` dictionary stores pairs in the format `{interface -> vlan_id}`.
When transmitting data, the following cases are considered:

1. **From a host to a switch** → A 4-byte tag containing the VLAN ID is added right after the MAC addresses, increasing the frame length by 4 bytes.
2. **From a switch to a host** → The frame is transmitted only if the VLAN ID of the port (towards the host) matches the tagged VLAN ID within the frame. The frame is also restructured by removing the VLAN tag and decreasing its length by 4 bytes.
3. **From a switch to another switch** → The frame is passed as is, ensuring that all frames transmitted through trunk ports and to switches are tagged.
4. **From a host to another host (via the same switch)** → If the hosts are connected to the same switch and belong to the same VLAN, the frame remains untagged and is transmitted only if the VLAN IDs of the two access ports are equal.

---

### Task 3: Simplified Spanning Tree Protocol (STP)
The STP algorithm initializes all ports as `Designated` within the `port_state` dictionary (`{port_number -> state_of_port}`).
Each switch has a priority (read from the configuration file), and the switch with the **lowest priority** is designated as the **root bridge**, with all its ports set to `Designated`.

#### STP Process:
1. Initially, every switch considers itself the root bridge, marking all ports as `Designated`.
2. **Global variables** are used for bridge IDs (`own_bridge_ID`, `root_bridge_ID`) and path costs (`root_path_cost`) to avoid excessive parameter passing.
3. **BPDU messages** are sent every second to establish the root bridge and port states, following the provided pseudocode.
4. BPDU messages are sent to a **special MAC address** to ensure correct processing.
5. BPDU structure includes:
   - Special destination MAC address
   - Source MAC address of the sending switch (`get_switch_mac()`)
   - LLC header length and content
   - BPDU configuration details (converted to bytes using `to_bytes`)
6. The **BPDU length** is 52 bytes (`BPDU_LEN`), and messages are transmitted across all trunk interfaces if the switch is the root bridge.
7. The `gather_info_bpdu` function extracts essential BPDU elements (bridge IDs and root path costs).
8. **Modification to VLAN logic:** Data can only be transmitted through **designated** ports. If a port is in a **blocked** state, no data is transmitted through it.

---

