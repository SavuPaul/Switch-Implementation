#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

own_bridge_ID = -1
root_bridge_ID = -1
root_path_cost = -1
root_port = -1
BPDU_LEN = 52

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

# Creates a bpdu package
def create_bpdu(sender_bridge_ID, port):
    # Destination MAC address
    d_mac_address = bytes([0x01, 0x80, 0xC2, 0x00, 0x00, 0x00])

    # Source MAC address
    s_mac_address = get_switch_mac()

    # Define length
    LLC_LEN = 38
    LLC_LEN = LLC_LEN.to_bytes(2, byteorder = 'big')

    # Define LLC header components
    DSAP = 0x42
    SSAP = 0x42
    CONTROL = 0x03

    # Define LLC header
    LLC_header = bytes([DSAP, SSAP, CONTROL])

    # Define bpdu header
    bpdu_header = bytes([0x00, 0x00])

    # Define bpdu configuration components
    bpdu_flags = bytes([0x00, 0x00])
    bpdu_root_bridge_id = root_bridge_ID.to_bytes(8, byteorder='big')
    bpdu_root_path_cost = root_path_cost.to_bytes(4, byteorder='big')
    bpdu_bridge_id = sender_bridge_ID.to_bytes(8, byteorder = 'big')
    bpdu_port = port.to_bytes(2, byteorder = 'big')
    bpdu_message_age = bytes([0x01])
    bpdu_max_age = bytes([0x14])
    bpdu_hello_time = bytes([0x02])
    bpdu_forward_delay = bytes([0x0F])

    # Concatenate them into one
    bpdu_conf = (bpdu_flags
                + bpdu_root_bridge_id
                + bpdu_root_path_cost
                + bpdu_bridge_id
                + bpdu_port
                + bpdu_message_age
                + bpdu_max_age
                + bpdu_hello_time
                + bpdu_forward_delay)

    return (d_mac_address + s_mac_address + LLC_LEN
            + LLC_header + bpdu_header + bpdu_conf)

# Send BPDU every second to trunk_ports from root
def send_bpdu_every_sec(trunk_ports):
    while True:
        if root_bridge_ID == own_bridge_ID:
            for port in trunk_ports:
                root_path_cost = 0
                bpdu = create_bpdu(own_bridge_ID, port)
                send_to_link(port, BPDU_LEN, bpdu)

        time.sleep(1)

# Function for receiving BPDU packages
def received_bpdu(bpdu, interface, trunk_ports, port_state):
    # Gather the important information from the package
    bpdu_root_bridge_ID, bpdu_sender_path_cost, bpdu_sender_bridge_ID = gather_info_bpdu(bpdu)

    global root_bridge_ID, root_path_cost, root_port

    if bpdu_root_bridge_ID < root_bridge_ID:
        root_bridge_ID = bpdu_root_bridge_ID
        root_path_cost = bpdu_sender_path_cost + 10
        root_port = interface

        for port in trunk_ports:
            if port != root_port:
                port_state[port] = 'Blocked'

        if port_state[root_port] == 'Blocked':
            port_state[root_port] = 'Designated'

        for port in trunk_ports:
            bpdu_package = create_bpdu(own_bridge_ID, port)
            send_to_link(port, BPDU_LEN, bpdu_package)
    
    elif bpdu_root_bridge_ID == root_bridge_ID:
        if interface == root_port and bpdu_sender_path_cost + 10 < root_path_cost:
            root_path_cost = bpdu_sender_path_cost + 10
        elif interface != root_port and bpdu_sender_path_cost > root_path_cost:
            if port_state[interface] == 'Blocked':
                port_state[interface] = 'Designated'
    
    elif bpdu_sender_bridge_ID == own_bridge_ID:
        port_state[interface] = 'Blocked'
    
    else:
        return

    if own_bridge_ID == root_bridge_ID:
        for port in trunk_ports:
            port_state[port] = 'Designated'


# Gets the important information from a bpdu package
def gather_info_bpdu(bpdu):
    bpdu_root_bridge_id = int.from_bytes(bpdu[22:29], 'big')
    bpdu_sender_path_cost = int.from_bytes(bpdu[30:33], 'big')
    bpdu_sender_bridge_id = int.from_bytes(bpdu[34:41], 'big')

    return bpdu_root_bridge_id, bpdu_sender_path_cost, bpdu_sender_bridge_id

# Determines whether or not the address is unicast based on the LSB
# of the first byte within the MAC address
def address_is_unicast(address):
    if address[0] & 0x01 == 0:
        return 1
    return 0

# Initialises a switch with priority, vlan_ids and gathers trunk ports
def initialise_switch(config_file):
    # Read the priority
    priority = config_file.readline()

    vlan_ids = {}
    trunk_ports = []
    items = []

    # Next lines contain the interface name and the vlan_id,
    # but only the vlan_id is stored
    for line in config_file:
        items.append(line.split(" ")[1].split("\n")[0])

    for i in range(len(items)):

        vlan_ids[i] = items[i]
        if items[i] == 'T':
            # Store the trunk ports
            trunk_ports.append(i)
        else:
            vlan_ids[i] = int(vlan_ids[i])

    return priority, vlan_ids, trunk_ports


def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]
    sw_id = int(switch_id)

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    # MAC Table dictionary
    mac_table = {}
    # Port state dictionary
    port_state = {}
    # Trunk ports array
    trunk_port = []

    # Open the switch configuration file
    config_file = open(f"./configs/switch{sw_id}.cfg", "r")

    # Initialise the vlan_id's and priorities
    priority, vlan_ids, trunk_port = initialise_switch(config_file)

    # Close the file
    config_file.close()

    # MAC destination for bpdu packages
    bpdu_mac_address = bytes([0x01, 0x80, 0xC2, 0x00, 0x00, 0x00])

    # own_bridge_id and root_bridge_id will be equal to priority
    priority = int(priority)
    global own_bridge_ID
    own_bridge_ID = priority
    global root_bridge_ID
    root_bridge_ID = own_bridge_ID

    # Since the initialisation perceives every switch as being the root bridge,
    # the cost from the root bridge to itself is equal to zero
    global root_path_cost
    root_path_cost = 0

    # Initialise, set all ports to designated
    if own_bridge_ID == root_bridge_ID:
        for port in interfaces:
            port_state[port] = 'Designated'

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending bpdu
    t = threading.Thread(target=send_bpdu_every_sec, args=(trunk_port,))
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        interface, data, length = recv_from_any_link()

        # Obtains the addresses
        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)
        dest_mac_non_hr = dest_mac
        src_mac_non_hr = src_mac

        # Check if destination mac is the bpdu specific one
        if dest_mac == bpdu_mac_address:
            received_bpdu(data, interface, trunk_port, port_state)
            continue

        # Add the source to the mac table, except for the broadcast address
        if src_mac_non_hr not in mac_table and src_mac_non_hr != 'ff:ff:ff:ff:ff:ff':
            mac_table[src_mac_non_hr] = interface

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # Implemented forwarding with learning
        # Implemented VLAN support
        # Implement STP support

        if address_is_unicast(dest_mac_non_hr):
            # Address is in the mac_table already
            if dest_mac_non_hr in mac_table:
                port = mac_table[dest_mac_non_hr]
                # Data cannot be sent through blocked ports
                if port_state[port] == 'Blocked':
                    continue
                elif vlan_ids[interface] == 'T':
                    # Frame is going through another trunk port (coming
                    # from trunk) or the frame is going through access
                    if vlan_ids[port] == 'T':
                        send_to_link(port, length, data)
                    else:
                        # Rebuild the package
                        send_to_link(port, length - 4, data[0:12] + data[16:])
                else:
                    # Frame is going through a trunk port (coming
                    # from access) or the frame is going through access
                    if vlan_ids[port] == 'T':
                        # Rebuild the package
                        send_to_link(port, length + 4, data[0:12] + create_vlan_tag(vlan_ids[interface]) + data[12:])
                    else:
                        send_to_link(port, length, data)
            else:
                for port in interfaces:
                    if port != interface:
                        # Data cannot be sent through blocked ports
                        if port_state[port] == 'Blocked':
                            continue
                        elif vlan_ids[interface] == 'T':
                            # Frame is going through another trunk port
                            # or through an access port
                            if vlan_ids[port] == 'T':
                                send_to_link(port, length, data)
                            else:
                                if vlan_ids[port] == vlan_id:
                                    send_to_link(port, length - 4, data[0:12] + data[16:])
                        else:
                            # Frame is coming from an access port
                            # and is going through a trunk port or
                            # going through an access port again
                            if vlan_ids[port] == 'T':
                                send_to_link(port, length + 4, data[0:12] + create_vlan_tag(vlan_ids[interface]) + data[12:])
                            else:
                                if vlan_ids[port] == vlan_ids[interface]:
                                    send_to_link(port, length, data)
        else:
            for port in interfaces:
                if port != interface:
                    if port_state[port] == 'Blocked':
                        continue
                    # The interface through which
                    # the frame passed is trunk
                    elif vlan_ids[interface] == 'T':
                        # The port to the next device is trunk
                        if vlan_ids[port] == 'T':
                            send_to_link(port, length, data)
                        else:
                            # Next stop is a host
                            if vlan_ids[port] == vlan_id:
                                send_to_link(port, length - 4, data[0:12] + data[16:])
                    else:
                        # The frame is coming from a host
                        # 1. to a switch
                        if vlan_ids[port] == 'T':
                            send_to_link(port, length + 4, data[0:12] + create_vlan_tag(vlan_ids[interface]) + data[12:])
                        else:
                            # 2. to a host (through only 1 switch)
                            if vlan_ids[port] == vlan_ids[interface]:
                                send_to_link(port, length, data)

if __name__ == "__main__":
    main()
