import sys
import re
import gzip
import pprint
import json
import pygame
import math

# Global list to store flow data across devices
source_ip_addr = "10.10.10.10"
#source_mac_addr = "c474.86d1.c325" # 1 spine, 2 vteps
source_mac_addr = "0481.502e.563f" # 4 devices, no vxlan
destination_ip_addr = "20.20.20.20"
#destination_mac_addr = "c43e.48ac.6a92" # 1 spine, 2 vteps
destination_mac_addr = "047f.ffca.1c55" # 4 devices, no vxlan

forward_flow_data = []
reverse_flow_data = []
frd_src_vtep_ip = ""
frd_dst_vtep_ip = ""
rvs_src_vtep_ip = ""
rvs_dst_vtep_ip = ""
frd_vni = ""
rvs_vni = ""
vxlan_ecap = False

def get_intersection(rect_center, target_center, rect_width, rect_height):
    #Calculate the intersection point on the edge of the rectangle.
    dx, dy = target_center[0] - rect_center[0], target_center[1] - rect_center[1]
    angle = math.atan2(dy, dx)
    
    if abs(dx) > abs(dy):  # Intersection on left or right side
        if dx > 0:  # Right side
            x = rect_center[0] + rect_width // 2
            y = rect_center[1] + (rect_width // 2) * math.tan(angle)
        else:  # Left side
            x = rect_center[0] - rect_width // 2
            y = rect_center[1] - (rect_width // 2) * math.tan(angle)
    else:  # Intersection on top or bottom side
        if dy > 0:  # Bottom side
            y = rect_center[1] + rect_height // 2
            x = rect_center[0] + (rect_height // 2) / math.tan(angle)
        else:  # Top side
            y = rect_center[1] - rect_height // 2
            x = rect_center[0] - (rect_height // 2) / math.tan(angle)
    
    return x, y

def get_reverse_flow(device_data, source_host_name, destination_host_name ):
    global reverse_flow_data, source_ip_addr, source_mac_addr, destination_ip_addr, destination_mac_addr
    device_num = 1
    first_hop_device = get_host_connected_device(device_data, destination_mac_addr)
    
    # Fill in the flow_data dictionary
    flow_data = {
        "device_num": device_num,
        "current_device": destination_host_name,
        "headers": {
            "srcIP": destination_ip_addr,
            "srcMAC": destination_mac_addr,
            "destIP": source_ip_addr,
            "destMAC": source_mac_addr
        },
        "next_device_name": first_hop_device
    }
    device_num += 1

    # Append the current device's flow data to the global list
    reverse_flow_data.append(flow_data)

    last_hop_device = get_host_connected_device(device_data, source_mac_addr)

     # Start the recursive next hop lookup                           
    reverse_flow_data, device_number = get_reverse_flow_next_hop_data(device_num, device_data, source_ip_addr, first_hop_device, last_hop_device)
    
    # Fill in the flow_data dictionary
    flow_data = {
        "device_num": device_number,
        "current_device": last_hop_device,
        "headers": {
            "srcIP": destination_ip_addr,
            "srcMAC": destination_mac_addr,
            "destIP": source_ip_addr,
            "destMAC": source_mac_addr
        },
        "next_device_name": source_host_name
    }
    # Append the current device's flow data to the global list
    reverse_flow_data.append(flow_data)

def get_forward_flow(device_data, source_host_name, destination_host_name ):
    global forward_flow_data, source_ip_addr, source_mac_addr, destination_ip_addr, destination_mac_addr
    device_num = 1
    first_hop_device = get_host_connected_device(device_data, source_mac_addr)
    
    # Fill in the flow_data dictionary
    flow_data = {
        "device_num": device_num,
        "current_device": source_host_name,
        "headers" : {
            "srcIP": source_ip_addr,
            "srcMAC": source_mac_addr,
            "destIP": destination_ip_addr,
            "destMAC": destination_mac_addr
        },
        "next_device_name": first_hop_device
    }
    device_num += 1

    # Append the current device's flow data to the global list
    forward_flow_data.append(flow_data)

    last_hop_device = get_host_connected_device(device_data, destination_mac_addr)

     # Start the recursive next hop lookup
    forward_flow_data, device_number = get_forward_flow_next_hop_data(device_num, device_data, destination_ip_addr, first_hop_device, last_hop_device)
    
    # Fill in the flow_data dictionary
    flow_data = {
        "device_num": device_number,
        "current_device": last_hop_device,
        "headers" : {
            "srcIP": source_ip_addr,
            "srcMAC": source_mac_addr,
            "destIP": destination_ip_addr,
            "destMAC": destination_mac_addr
        },
        "next_device_name": destination_host_name
    }
    # Append the current device's flow data to the global list
    forward_flow_data.append(flow_data)

def get_reverse_flow_next_hop_data(device_num, device_data, next_hop_ip, device_name, last_hop_device):
    global reverse_flow_data, source_ip_addr, source_mac_addr, destination_ip_addr, destination_mac_addr
    routing_table_data = device_data[device_name]["routing_table_data"]
    arp_table_data = device_data[device_name]["arp_table_data"]
    vxlan_interface_data = device_data[device_name]["vxlan_interface_data"]
    global rvs_src_vtep_ip
    vlan_to_vni_mapping = ""
    for item in vxlan_interface_data:
        rvs_src_vtep_ip = item["source_interface_ip"]
        vlan_to_vni_mapping = item["vlan_to_vni_mapping"]
    global rvs_dst_vtep_ip
    global rvs_vni
    route_found = False
    arp_found = False
    nextHopMacAddr = ""
    next_device_name = ""
    current_device = ""
    exitIntf = ""
    global vxlan_ecap
    nextHop = ""
    nextHop_spine = ""
    found_host_route = False
    device_mac = ""

    # Check if the route is present on VTEP then mark ENCAP and get flood VTEP IPs
    for route_list in routing_table_data:
        for route in route_list:
            if rvs_dst_vtep_ip != "":  # checking for remote vtep IP on spine
                found_host_route, exitIntf, nextHop = check_host_route(route, rvs_dst_vtep_ip)
            elif rvs_dst_vtep_ip == "":  # checking for next hop IP
                found_host_route, exitIntf, nextHop = check_host_route(route, source_ip_addr)
            
            if found_host_route and "Vlan" in exitIntf:
                exitIntf = exitIntf.replace("Vlan", "")
                for item in vlan_to_vni_mapping:
                    if item["vlan"] == int(exitIntf):
                        rvs_vni = item["vni"]
                vlan_ports = get_host_vlan_port(device_data, device_name, exitIntf)
                if "Vx1" in vlan_ports:
                    flood_vtep_ips = get_flood_vtep_ips(device_data, device_name, exitIntf)
                    vxlan_ecap = True

            if found_host_route and not "Vlan" in exitIntf:
                for arp_list in arp_table_data:
                    for arp_entry in arp_list:
                        arp_found, macAddr = check_host_arp(arp_entry, nextHop)
                        if arp_found:
                            current_device = device_name
                            nextHopMacAddr = macAddr
                            next_device_name = get_hostname(nextHopMacAddr, device_data)
                            device_mac = get_mac_addr(device_name, device_data)

                            # Fill in the flow_data dictionary
                            if vxlan_ecap:
                                flow_data = {
                                    "device_num": device_num,
                                    "current_device": current_device,
                                    "headers": {
                                        "outer_destMAC": nextHopMacAddr,
                                        "outer_srcMAC": device_mac,
                                        "outer_destIP": rvs_dst_vtep_ip,
                                        "outer_srcIP": rvs_src_vtep_ip,
                                        "vni": rvs_vni,
                                        "inner_destMAC": source_mac_addr,
                                        "inner_srcMAC": destination_mac_addr,
                                        "inner_destIP": source_ip_addr,
                                        "inner_srcIP": destination_ip_addr
                                    },
                                    "next_device_name": next_device_name
                                }
                                device_num += 1
                                reverse_flow_data.append(flow_data)

                                if next_device_name == last_hop_device:
                                    return reverse_flow_data, device_num

                                # Recursively check if the next device is the last hop
                                return get_reverse_flow_next_hop_data(device_num, device_data, rvs_dst_vtep_ip, next_device_name, last_hop_device)
                            else:
                                flow_data = {
                                    "device_num": device_num,
                                    "current_device": current_device,
                                    "headers": {
                                        "srcIP": destination_ip_addr,
                                        "srcMAC": device_mac,
                                        "destIP": source_ip_addr,
                                        "destMAC": nextHopMacAddr
                                    },
                                    "next_device_name": next_device_name
                                }
                                device_num += 1
                                reverse_flow_data.append(flow_data)

                                if next_device_name == last_hop_device:
                                    return reverse_flow_data, device_num

                                # Recursively check if the next device is the last hop
                                return get_reverse_flow_next_hop_data(device_num, device_data, source_ip_addr, next_device_name, last_hop_device)
                            
    if vxlan_ecap:
        for route_list in routing_table_data:
            for route in route_list:
                if flood_vtep_ips:
                    for ip in flood_vtep_ips:
                        found_host_route, exitIntf, nextHop = check_host_route(route, ip)
                        if found_host_route and nextHop != "":
                            route_found = True
                            nextHop_spine = nextHop
                            rvs_dst_vtep_ip = ip
                            break

                        if route_found:
                            for arp_list in arp_table_data:
                                for arp_entry in arp_list:
                                    arp_found, macAddr = check_host_arp(arp_entry, nextHop_spine)
                                    if arp_found:
                                        current_device = device_name
                                        nextHopMacAddr = macAddr
                                        next_device_name = get_hostname(nextHopMacAddr, device_data)
                                        device_mac = get_mac_addr(device_name, device_data)

                            flow_data = {
                                "device_num": device_num,
                                "current_device": current_device,
                                "headers": {
                                    "outer_destMAC": nextHopMacAddr,
                                    "outer_srcMAC": device_mac,
                                    "outer_destIP": rvs_dst_vtep_ip,
                                    "outer_srcIP": rvs_src_vtep_ip,
                                    "vni": rvs_vni,
                                    "inner_destMAC": source_mac_addr,
                                    "inner_srcMAC": destination_mac_addr,
                                    "inner_destIP": source_ip_addr,
                                    "inner_srcIP": destination_ip_addr
                                },
                                "next_device_name": next_device_name
                            }
                            device_num += 1
                            reverse_flow_data.append(flow_data)

                            if next_device_name == last_hop_device:
                                return reverse_flow_data, device_num

                            return get_reverse_flow_next_hop_data(device_num, device_data, rvs_dst_vtep_ip, next_device_name, last_hop_device)
                        
    return reverse_flow_data, device_num

def get_host_vlan_port(device_data, device_name, exitIntf):
    vlan_ports = device_data[device_name]["vlan_table_data"]
    for items in vlan_ports:
        for data in items:
            if data["vlan_num"] == exitIntf:
                return data["vlan_ports"]

def get_flood_vtep_ips(device_data, device_name, exitIntf):
    vtep_ips = device_data[device_name]["vxlan_interface_data"]
    for items in vtep_ips:
        for data in items["headend_replication_list"]:
            if data["vlan"] == exitIntf:
                return data["vtep_ips"]

def get_forward_flow_next_hop_data(device_num, device_data, next_hop_ip, device_name, last_hop_device):
    global forward_flow_data, source_ip_addr, source_mac_addr, destination_ip_addr, destination_mac_addr
    routing_table_data = device_data[device_name]["routing_table_data"]
    arp_table_data = device_data[device_name]["arp_table_data"]
    vxlan_interface_data = device_data[device_name]["vxlan_interface_data"]
    global frd_src_vtep_ip
    global vlan_to_vni_mapping
    for item in vxlan_interface_data:
        frd_src_vtep_ip = item["source_interface_ip"]
        vlan_to_vni_mapping = item["vlan_to_vni_mapping"]
    global frd_dst_vtep_ip
    global frd_vni
    route_found = False
    arp_found = False
    nextHopMacAddr = ""
    next_device_name = ""
    current_device = ""
    exitIntf = ""
    global vxlan_ecap
    nextHop = ""
    nextHop_spine = ""
    found_host_route = False
    device_mac = ""
    flood_vtep_ips = []

    # Check if the route is present on VTEP then mark ENCAP and get flood VTEP IPs
    for route_list in routing_table_data:
        for route in route_list:
            if frd_dst_vtep_ip != "":  # checking for remote vtep IP on spine
                found_host_route, exitIntf, nextHop = check_host_route(route, frd_dst_vtep_ip)
            elif frd_dst_vtep_ip == "":  # checking for next hop IP
                found_host_route, exitIntf, nextHop = check_host_route(route, destination_ip_addr)
            
            if found_host_route and "Vlan" in exitIntf:
                exitIntf = exitIntf.replace("Vlan", "")
                for item in vlan_to_vni_mapping:
                    if item["vlan"] == int(exitIntf):
                        frd_vni = item["vni"]
                vlan_ports = get_host_vlan_port(device_data, device_name, exitIntf)
                if "Vx1" in vlan_ports:
                    flood_vtep_ips = get_flood_vtep_ips(device_data, device_name, exitIntf)
                    vxlan_ecap = True

            if found_host_route and not "Vlan" in exitIntf:
                for arp_list in arp_table_data:
                    for arp_entry in arp_list:
                        arp_found, macAddr = check_host_arp(arp_entry, nextHop)
                        if arp_found:
                            current_device = device_name
                            nextHopMacAddr = macAddr
                            next_device_name = get_hostname(nextHopMacAddr, device_data)
                            device_mac = get_mac_addr(device_name, device_data)

                            # Fill in the flow_data dictionary
                            if vxlan_ecap:
                                flow_data = {
                                    "device_num": device_num,
                                    "current_device": current_device,
                                    "headers": {
                                        "outer_destMAC": nextHopMacAddr,
                                        "outer_srcMAC": device_mac,
                                        "outer_destIP": frd_dst_vtep_ip,
                                        "outer_srcIP": frd_src_vtep_ip,
                                        "vni": frd_vni,
                                        "inner_destMAC": destination_mac_addr,
                                        "inner_srcMAC": source_mac_addr,
                                        "inner_destIP": destination_ip_addr,
                                        "inner_srcIP": source_ip_addr
                                    },
                                    "next_device_name": next_device_name
                                }
                                device_num += 1
                                forward_flow_data.append(flow_data)

                                if next_device_name == last_hop_device:
                                    return forward_flow_data, device_num

                                # Recursively check if the next device is the last hop
                                return get_forward_flow_next_hop_data(device_num, device_data, frd_dst_vtep_ip, next_device_name, last_hop_device)
                            else:
                                flow_data = {
                                    "device_num": device_num,
                                    "current_device": current_device,
                                    "headers" : {
                                        "srcIP": source_ip_addr,
                                        "srcMAC": device_mac,
                                        "destIP": destination_ip_addr,
                                        "destMAC": nextHopMacAddr
                                    },
                                    "next_device_name": next_device_name
                                }
                                device_num += 1
                                forward_flow_data.append(flow_data)

                                if next_device_name == last_hop_device:
                                    return forward_flow_data, device_num

                                # Recursively check if the next device is the last hop
                                return get_forward_flow_next_hop_data(device_num, device_data, destination_ip_addr, next_device_name, last_hop_device)
    
    if vxlan_ecap:
        for route_list in routing_table_data:
            for route in route_list:
                if flood_vtep_ips:
                    for ip in flood_vtep_ips:
                        found_host_route, exitIntf, nextHop = check_host_route(route, ip)
                        if found_host_route and nextHop != "":
                            route_found = True
                            nextHop_spine = nextHop
                            frd_dst_vtep_ip = ip
                            break

                        if route_found:
                            for arp_list in arp_table_data:
                                for arp_entry in arp_list:
                                    arp_found, macAddr = check_host_arp(arp_entry, nextHop_spine)
                                    if arp_found:
                                        current_device = device_name
                                        nextHopMacAddr = macAddr
                                        next_device_name = get_hostname(nextHopMacAddr, device_data)
                                        device_mac = get_mac_addr(device_name, device_data)

                            flow_data = {
                                "device_num": device_num,
                                "current_device": current_device,
                                "headers": {
                                    "outer_destMAC": nextHopMacAddr,
                                    "outer_srcMAC": device_mac,
                                    "outer_destIP": frd_dst_vtep_ip,
                                    "outer_srcIP": frd_src_vtep_ip,
                                    "vni": frd_vni,
                                    "inner_destMAC": destination_mac_addr,
                                    "inner_srcMAC": source_mac_addr,
                                    "inner_destIP": destination_ip_addr,
                                    "inner_srcIP": source_ip_addr
                                },
                                "next_device_name": next_device_name
                            }
                            device_num += 1
                            forward_flow_data.append(flow_data)

                            if next_device_name == last_hop_device:
                                return forward_flow_data, device_num

                            return get_forward_flow_next_hop_data(device_num, device_data, frd_dst_vtep_ip, next_device_name, last_hop_device)
                        
    return forward_flow_data, device_num

def get_hostname(nextHopMacAddr, device_data):
    for _, data in device_data.items():
        if nextHopMacAddr == data["system_mac"]:
            next_device_name = data["hostname"]
    return next_device_name

def get_mac_addr(device_name, device_data):
    for _, data in device_data.items():
        if device_name == data["hostname"]:
            device_mac = data["system_mac"]
    return device_mac

def check_host_arp(arp_entry, hostIP):
    host_mac = ""
    arp_found = False

    if arp_entry['ipAdd'] == hostIP:
        host_mac = arp_entry['macAddr']
        arp_found = True

    return arp_found, host_mac

def ip_to_binary(ip_address):
    octets = ip_address.split(".")
    binary_octets = []
    
    for octet in octets:
        binary_octet = format(int(octet), "08b")  # Convert octet to binary string
        binary_octets.append(binary_octet)
    
    binary_ip = ".".join(binary_octets)
    return binary_ip

def check_host_route(route, hostIP):
    host_binary_ip = ip_to_binary(hostIP)
    host_binary_ip = host_binary_ip.replace(".", "")
    matching_ip = None
    exitIntf = ""
    nextHop = ""
    route_found = False

    network_prifix = route['network']
    ip, mask = str(network_prifix).split("/")
    binary_ip = ip_to_binary(ip.replace("['", ""))
    net_mask = mask.replace("']", "")
    network_ip = binary_ip.replace(".", "")

    if network_ip[:int(net_mask)] == host_binary_ip[:int(net_mask)]:
        matching_ip = network_ip
        nextHop = route["next_hop"].strip("['']")
        exitIntf = route["exit_interface"][0].strip("'")

    if matching_ip:
        octets = [matching_ip[i:i+8] for i in range(0, len(matching_ip), 8)]
        decimal_octets = [str(int(octet, 2)) for octet in octets]
        ip_address = ".".join(decimal_octets)
        net_prfix = ip_address + "/" + net_mask

        tmp = route["network"]
        ip_mask = str(tmp).strip("['']")
        if ip_mask == net_prfix:
            nextHop = route["next_hop"].strip("['']")
            exitIntf = route["exit_interface"][0].strip("'")
        
        if nextHop != "directly connected":
            route_found = True
            return route_found, exitIntf, nextHop
        elif nextHop == "directly connected" and "Vlan" in exitIntf:
            route_found = True
            return route_found, exitIntf, nextHop
    return route_found, exitIntf, nextHop

def get_host_connected_device(device_data, mac_addr):
    host_connected_device = ""
    for hostname, data in device_data.items():
        # Check if source_host_data is not empty
        if data.get("source_host_data"):
            for source_host in data["source_host_data"]:
                # Check if the src_mac_addr matches source_host_data["mac_addr"]
                if source_host.get("mac_addr") == mac_addr:
                    #host_connected_vlanID = source_host.get("vlanID")
                    #host_connected_interface = source_host.get("exit_port")
                    host_connected_device = hostname
        elif data.get("destination_host_data"):
            for destination_host in data["destination_host_data"]:
                # Check if the src_mac_addr matches source_host_data["mac_addr"]
                if destination_host.get("mac_addr") == mac_addr:
                    #host_connected_vlanID = destination_host.get("vlanID")
                    #host_connected_interface = destination_host.get("exit_port")
                    host_connected_device = hostname
    return host_connected_device #, host_connected_vlanID, host_connected_interface 

def get_vxlan_interface_data(vxlan_output):
    vxlan_data = {
        "source_interface_ip": None,
        "virtual_vtep_ip": None,
        "flood_list_source": None,
        "remote_mac_learning": None,
        "vlan_to_vni_mapping": [],
        "headend_replication_list": []
    }

    # Regular expressions for extracting the required information
    source_interface_re = re.compile(r'^\s*Source interface.*with\s+(\d+\.\d+\.\d+\.\d+)')
    virtual_vtep_ip_re = re.compile(r'^\s*Virtual VTEP IP address is\s+(\d+\.\d+\.\d+\.\d+)')
    flood_mode_re = re.compile(r'^\s*Replication/Flood Mode.*Source:\s+(\w+)')
    remote_mac_learning_re = re.compile(r'^\s*Remote MAC learning via\s+(\w+)')
    headend_repl_re = re.compile(r'^\s*(\d+)\s+((\d+\.\d+\.\d+\.\d+\s+)+)')

    # Process each line of the output
    for line in vxlan_output.splitlines():
        source_interface_match = source_interface_re.search(line)
        virtual_vtep_ip_match = virtual_vtep_ip_re.search(line)
        flood_mode_match = flood_mode_re.search(line)
        remote_mac_learning_match = remote_mac_learning_re.search(line)
        vlan_to_vni_match = re.findall(r'\[(\d+),\s*(\d+)\]', line)
        headend_repl_match = headend_repl_re.search(line)

        if source_interface_match:
            vxlan_data["source_interface_ip"] = source_interface_match.group(1)
        elif virtual_vtep_ip_match:
            vxlan_data["virtual_vtep_ip"] = virtual_vtep_ip_match.group(1)
        elif flood_mode_match:
            vxlan_data["flood_list_source"] = flood_mode_match.group(1)
        elif remote_mac_learning_match:
            vxlan_data["remote_mac_learning"] = remote_mac_learning_match.group(1)
        elif vlan_to_vni_match:
            for vlan, vni in vlan_to_vni_match:
                vlan_vni_data = {
                    "vlan": int(vlan),
                    "vni": int(vni)
                }
                vxlan_data["vlan_to_vni_mapping"].append(vlan_vni_data)
        elif headend_repl_match:
            # Capture all IPs in the line
            vlan = headend_repl_match.group(1)
            ips = headend_repl_match.group(2).split()

            vxlan_data["headend_replication_list"].append({
                "vlan": vlan,
                "vtep_ips": ips
            })

    return vxlan_data

def get_vlan_data(vlan_table_data):
    vlan_data = []
    current_vlan = None

    # Process each line of the output
    for line in vlan_table_data.splitlines():
        # Match lines with VLAN information
        vlan_match = re.match(r'^(\d+)\s+\S+\s+\S+\s+(.+)', line)
        if vlan_match:
            current_vlan = vlan_match.group(1)
            ports = vlan_match.group(2).replace(' ', '').split(',')
            vlan_data.append({
                "vlan_num": current_vlan,
                "vlan_ports": ports
            })
        elif current_vlan and line.strip():
            # Match additional port lines
            ports = line.strip().replace(' ', '').split(',')
            vlan_data[-1]["vlan_ports"].extend(ports)

    return vlan_data

def get_arp_data(arp_table):
    lines = arp_table.strip().split('\n')
    header = lines[1].split()
    arp_data = []

    for line in lines[2:]:
        columns = line.split()
        arp_entry = {
            "ipAdd": columns[0],
            "macAddr": columns[2],
            "learntPort": " ".join(columns[3:])
        }
        arp_data.append(arp_entry)

    return arp_data

def get_routing_table_data(routing_table):
    start_marker = "Gateway of last resort is not set"
    end_marker = "! IP routing not enabled"

    start_index = routing_table.find(start_marker) + len(start_marker)
    end_index = routing_table.find(end_marker)

    captured_data = routing_table[start_index:end_index].strip()
    lines = captured_data.strip().split('\n')
    route_type_pattern = r"^\s*([A-Z])"
    ip_with_mask_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}"
    ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3},"
    interface_pattern = r", (\S+)$"

    routing_data = []
    for line in lines:
        route_type_match = re.search(route_type_pattern, line)
        ip_with_mask_matches = re.findall(ip_with_mask_pattern, line)
        ip_matches = re.findall(ip_pattern, line)
        exit_int_matches = re.findall(interface_pattern, line)
        if ip_with_mask_matches:
            route_type = route_type_match.group(1)
            if ip_matches == []:
                routing = {
                    "network" : ip_with_mask_matches,
                    "route_type" : route_type,
                    "next_hop" : "directly connected",
                    "exit_interface" : exit_int_matches
                }
            else:
                routing = {
                    "network" : ip_with_mask_matches,
                    "route_type" : route_type,
                    "next_hop" : str(ip_matches).replace(",", ""),
                    "exit_interface" : exit_int_matches
                }
            routing_data.append(routing)
    return routing_data

def check_host_mac_entry(mac_address_table, host_mac_addr):
    host_vlanID = ""
    host_exit_port = ""
    for data in mac_address_table:
        if data['macAddr'] == host_mac_addr:
            host_vlanID = data['vlanID']
            host_exit_port = data['learntPort']

    return host_vlanID, host_exit_port

def get_mac_address_data(mac_table):
    start_marker = "Vlan    Mac Address       Type        Ports      Moves   Last Move"
    end_marker = "Total Mac Addresses for this criterion:"

    start_index = mac_table.find(start_marker) + len(start_marker)
    end_index = mac_table.find(end_marker)

    captured_data = mac_table[start_index:end_index].replace("-", "").strip()
    lines = captured_data.strip().split('\n')

    mac_entries = []

    for line in lines:
        columns = line.split()
        if len(columns) >= 4:  # Ensure at least 4 columns are present
            entry = {
                "vlanID": columns[0],
                "macAddr": columns[1],
                "learntPort": columns[3]
            }
            mac_entries.append(entry)

    return mac_entries 

def get_lldp_nei(lldpNeighbors,device_dict):
    # Define the regex pattern for the initial match
    lldp_pattern = r'Interface Ethernet\d+(?:/\d+)? detected \d+ LLDP neighbors:'
    nei_data_dict = {}
    # Use regex to find and store matches
    matches = re.findall(lldp_pattern, lldpNeighbors)
    # Iterate through matches and store them as keys with their corresponding data
    for match in matches:
        temp = match.strip()
        neighbour_key = temp.split(" ")[1]
        # Find the data following the matched pattern
        data_after_match = re.search(f'{re.escape(match)}(.*?)Interface Ethernet', lldpNeighbors, re.DOTALL)
        if data_after_match:
            value = data_after_match.group(1).strip()
            if value:  # Check if the value is not empty
                neighbor_pattern = r'Neighbor\s([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\/"([a-zA-Z0-9_]+)"'
                neighbor_match = re.search(neighbor_pattern, value)
                if neighbor_match:
                    mac_address = neighbor_match.group(1)
                    interface_name = neighbor_match.group(2)
                neighbor_name_pattern = r'- System Name:\s*"([^"]*)"'

                neighbor_name_match = re.search(neighbor_name_pattern, value)
                if neighbor_name_match:
                    system_name = neighbor_name_match.group(1)
                nei_data_dict[neighbour_key] = {
                    "mac_address": mac_address,
                    "interface_name": interface_name,
                    "system_name": system_name
                }

    # Example of how you might append this to the device_dict
    for neighbour_key, data in nei_data_dict.items():
        neighbour_entry = {
            "local_int": neighbour_key,
            "neighbour_mac": data["mac_address"],
            "neighbour_int": data["interface_name"],
            "neighbour_system": data["system_name"]
        }
        device_dict["neighbours"].append(neighbour_entry)

def process_file(file_path, key_value_dict):
    sections = {}  # To store the sections
    current_section = None

    with gzip.open(file_path, 'rt') as f:
        for line in f:
            section_match = re.match(r'^-+ show (.+?) -+$', line.strip())
            if section_match:
                current_section = section_match.group(1)
                sections["show " + current_section] = ''
            elif current_section is not None:
                sections["show " + current_section] += line

    # Remove leading and trailing whitespace from section content
    sections = {key: value.strip() for key, value in sections.items()}

    # Store key-value pairs in the dictionary
    for key, value in sections.items():
        key_value_dict[key] = value

def initialize_device_dict():
    return {
        "system_mac": "",
        "neighbours": [],
        "source_host_data": [],
        "destination_host_data": [],
        "routing_table_data": [],
        "arp_table_data": [],
        "vlan_table_data": [],
        "vxlan_interface_data": []
    }

def main():
    device_data = {}
    source_host_name = ""
    destination_host_name = ""
    
    # Check if the correct number of command-line arguments is provided
    if len(sys.argv) < 2:
        print("Usage: python script_name.py num_files file1.gz file2.gz ...")
        return
    else:
        try:
            num_files = int(sys.argv[1])
            file_count = 0
            key_value_dict = {}
            # Iterate over the rest of the arguments to process file names
            for arg in sys.argv[2:]:
                if arg.endswith('.gz'):
                    file_count += 1
                    hostname = ""
                    device_dict = initialize_device_dict()
                    # Process the file
                    process_file(arg, key_value_dict)

                    running_config = key_value_dict.get("show running-config sanitized", "")
                    lines = running_config.strip().split('\n')
                    for line in lines:
                        if "hostname" in line:
                            hostname = line.strip().split(" ")[1]
                    device_dict["hostname"] = hostname
                    systemVersion = key_value_dict.get("show version detail","")
                    lines = systemVersion.strip().split('\n')
                    for line in lines:
                        if "System MAC address" in line:
                            systemMAC = line.strip().split(":")[1].strip()
                    device_dict["system_mac"] = systemMAC

                    lldpNeighbors = key_value_dict.get("show lldp neighbors detail","")
                    get_lldp_nei(lldpNeighbors, device_dict)
                    for item in device_dict["neighbours"]:
                        if item["neighbour_mac"] == source_mac_addr:
                            source_host_name = item["neighbour_system"]
                        if item["neighbour_mac"] == destination_mac_addr:
                            destination_host_name = item["neighbour_system"]

                    mac_address_table_data = key_value_dict.get("show mac address-table", "")
                    mac_address_data = get_mac_address_data(mac_address_table_data)
                    if mac_address_data != []:
                        # Create a separate dictionary for the source host data
                        src_host_data = {
                            "vlanID": "",
                            "mac_addr": "",
                            "exit_port": ""
                        }
                        src_vlanID, src_exit_port = check_host_mac_entry(mac_address_data, source_mac_addr)
                        if src_vlanID != "" and src_exit_port != "":
                            if "Et" in src_exit_port:
                                src_exit_port = src_exit_port.replace("Et", "Ethernet")
                            src_host_data["vlanID"] = src_vlanID
                            src_host_data["mac_addr"] = source_mac_addr
                            src_host_data["exit_port"] = src_exit_port
                            device_dict["source_host_data"].append(src_host_data)

                        # Create a separate dictionary for the destination host data
                        dst_host_data = {
                            "vlanID": "",
                            "mac_addr": "",
                            "exit_port": ""
                        }
                        dst_vlanID, dst_exit_port = check_host_mac_entry(mac_address_data, destination_mac_addr)
                        if dst_vlanID != "" and dst_exit_port != "":
                            if "Et" in dst_exit_port:
                                dst_exit_port = dst_exit_port.replace("Et", "Ethernet")
                            dst_host_data["vlanID"] = dst_vlanID
                            dst_host_data["mac_addr"] = destination_mac_addr
                            dst_host_data["exit_port"] = dst_exit_port
                            device_dict["destination_host_data"].append(dst_host_data)

                    #Routing Table
                    routing_table_data = key_value_dict.get("show ip route vrf all detail", "")
                    routing_table = get_routing_table_data(routing_table_data)
                    device_dict["routing_table_data"].append(routing_table)

                    #ARP for SIP and DIP
                    arp_table_entries = key_value_dict.get("show arp vrf all", "")
                    arp_table_data = get_arp_data(arp_table_entries)
                    device_dict["arp_table_data"].append(arp_table_data)

                    #VLAN table data
                    vlan_table_data = key_value_dict.get("show vlan", "")
                    vlan_table = get_vlan_data(vlan_table_data)
                    device_dict["vlan_table_data"].append(vlan_table)

                    #VXLAN Interface data
                    vxlan_interface_data = key_value_dict.get("show interface vxlan 1-$", "")
                    if vxlan_interface_data != "":
                        vxlan_interface = get_vxlan_interface_data(vxlan_interface_data)
                        device_dict["vxlan_interface_data"].append(vxlan_interface)

                    device_data[hostname] = device_dict

                    # Stop processing files once the desired number of files is reached
                    if file_count >= num_files:
                        break

        except ValueError:
            print("Invalid input. Please provide a valid number of files.")
        
    # Write the device_data dictionary to a JSON file
    device_data_file = "device_data.json"  # Specify the output JSON file name
    with open(device_data_file, 'w') as json_file:
        json.dump(device_data, json_file, indent=4)

    get_forward_flow(device_data, source_host_name, destination_host_name)
    get_reverse_flow(device_data, source_host_name, destination_host_name)

    # Extract device names and system MACs
    device_names = []
    for items in forward_flow_data:
        device = items['current_device']
        device_names.append(device)
    
    device_names = device_names[1:]
    system_macs = [device_data[device]['system_mac'] for device in device_names]
    num_devices = len(device_names)

    # Adjust screen dimensions based on the number of devices
    screen_width = 400 * num_devices
    screen_height = 600

    # Initialize Pygame
    pygame.init()

    # Set the dimensions of the screen
    screen = pygame.display.set_mode((screen_width, screen_height))

    # Set the title of the window
    pygame.display.set_caption("Device Topology with Hosts")

    # Define the rectangle dimensions
    rect_width = 100
    rect_height = 50

    # Calculate the spacing between rectangles
    spacing = (screen_width - (rect_width * num_devices)) // (num_devices + 1)

    # Set up the font
    font = pygame.font.SysFont(None, 24)
    font2 = pygame.font.SysFont(None, 18)

    # Create a dictionary to hold the positions and rectangles for each device
    rect_positions = {}
    rectangles = {}
    source_host_pos = {}
    destination_host_pos = {}
    packet_path = []

    # Calculate the positions for the devices and draw them
    for i in range(num_devices):
        rect_x = spacing + i * (rect_width + spacing)
        rect_y = (screen_height - rect_height) // 2
        rect = pygame.Rect(rect_x, rect_y, rect_width, rect_height)
        
        # Store the center position and rectangle for each device
        rect_positions[device_names[i]] = rect.center
        rectangles[device_names[i]] = rect
        for item in forward_flow_data:
            if item["current_device"] == device_names[i]:
                item["packet_pos"] = rect.center
        for item in reverse_flow_data:
            if item["current_device"] == device_names[i]:
                item["packet_pos"] = rect.center

    # Add the host positions to the rect_positions dictionary
    for device in device_data:
        for neighbour in device_data[device].get('neighbours', []):
            host_mac = neighbour['neighbour_mac']
            if host_mac == source_mac_addr:  # MACs of H1 and H2
                host_name = neighbour['neighbour_system']
                #source_host_name = host_name

                # Host position: a small circle above the switch
                host_pos = (rect_positions[device][0], rect_positions[device][1] - rect_height // 2 - 150)

                # Store the host position
                source_host_pos[host_name] = host_pos
                for item in forward_flow_data:
                    if item["current_device"] == host_name:
                        item["packet_pos"] = host_pos
                for item in reverse_flow_data:
                    if item["current_device"] == host_name:
                        item["packet_pos"] = host_pos
            if host_mac == destination_mac_addr:  # MACs of H1 and H2
                host_name = neighbour['neighbour_system']
                #destination_host_name = host_name

                # Host position: a small circle above the switch
                host_pos = (rect_positions[device][0], rect_positions[device][1] - rect_height // 2 - 150)

                # Store the host position
                destination_host_pos[host_name] = host_pos
                for item in forward_flow_data:
                    if item["current_device"] == host_name:
                        item["packet_pos"] = host_pos
                for item in reverse_flow_data:
                    if item["current_device"] == host_name:
                        item["packet_pos"] = host_pos
    
    forward_flow_data_file = "forward_flow_data.json"
    with open(forward_flow_data_file, 'w') as json_file:
        json.dump(forward_flow_data, json_file, indent=4)

    reverse_flow_data_file = "reverse_flow_data.json"
    with open(reverse_flow_data_file, 'w') as json_file:
        json.dump(reverse_flow_data, json_file, indent=4)

    packet_path.append(source_host_pos[source_host_name])
    for device in rect_positions:
        packet_path.append(rect_positions[device])
    packet_path.append(destination_host_pos[destination_host_name])

    # Set the initial packet position and speed
    packet_pos = list(packet_path[0])
    packet_speed = 1.5
    path_index = 1
    headers_text_data = {}

    # Set up the clock to control the frame rate
    clock = pygame.time.Clock()

    # Game loop
    running = True
    while running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False

        # Fill the screen with a color (optional)
        screen.fill((255, 255, 255))  # White background

        # Draw rectangles and add labels for each device
        for i in range(num_devices):
            rect_x = spacing + i * (rect_width + spacing)
            rect_y = (screen_height - rect_height) // 2
            rect = pygame.Rect(rect_x, rect_y, rect_width, rect_height)
            
            # Store the center position and rectangle for each device
            rect_positions[device_names[i]] = rect.center
            rectangles[device_names[i]] = rect

            # Draw the rectangle
            pygame.draw.rect(screen, (66, 135, 245), rect)  # Blue rectangle

            # Render the device name text
            name_surface = font.render(device_names[i], True, (255, 255, 255))  # White text
            name_rect = name_surface.get_rect(center=rect.center)  # Center the text in the rectangle
            
            # Render the system_mac text
            mac_surface = font.render(system_macs[i], True, (0, 0, 0))  # Black text
            mac_rect = mac_surface.get_rect(center=(rect.centerx, rect.centery + rect_height//2 + 10))  # Position below the rectangle
            
            # Blit the text onto the screen
            screen.blit(name_surface, name_rect)
            screen.blit(mac_surface, mac_rect)

        # Draw lines between devices to represent connections and add local_int labels
        for device in device_data:
            for neighbour in device_data[device].get('neighbours', []):
                neighbour_name = neighbour['neighbour_system']
                local_int = neighbour['local_int']
                # Draw a line from the edge of the current device to the edge of the neighbour device
                if device in rect_positions and neighbour_name in rect_positions:
                    start_pos = get_intersection(rect_positions[device], rect_positions[neighbour_name], rect_width, rect_height)
                    end_pos = get_intersection(rect_positions[neighbour_name], rect_positions[device], rect_width, rect_height)
                    pygame.draw.line(screen, (0, 0, 0), start_pos, end_pos, 2)
                    
                    # Calculate a point closer to the start position for the local_int label
                    int_label_pos = (
                        start_pos[0] + 0.2 * (end_pos[0] - start_pos[0]),
                        start_pos[1] + 0.2 * (end_pos[1] - start_pos[1]) - 10  # Move up by 10 pixels
                    )
                    
                    # Render the local_int text
                    local_int_surface = font.render(local_int, True, (0, 0, 0))  # Black text
                    local_int_rect = local_int_surface.get_rect(center=int_label_pos)
                    
                    # Blit the local_int text onto the screen
                    screen.blit(local_int_surface, local_int_rect)

                # Draw circles for hosts and connect them to the corresponding device
                host_mac = neighbour['neighbour_mac']
                if host_mac == source_mac_addr or host_mac == destination_mac_addr:
                    host_name = neighbour['neighbour_system']
                    local_int = neighbour['local_int']

                    # Host position: a small circle above the switch
                    host_pos = (rect_positions[device][0], rect_positions[device][1] - rect_height // 2 - 150)

                    # Draw the line from the top of the switch to the host
                    start_pos = (rect_positions[device][0], rect_positions[device][1] - rect_height // 2)
                    pygame.draw.line(screen, (0, 0, 0), start_pos, host_pos, 2)

                    # Draw the host circle
                    pygame.draw.circle(screen, (66, 135, 245), host_pos, 20)  # Blue circle for the host

                    # Render the host name
                    host_name_surface = font.render(host_name, True, (255, 255, 255))  # White text
                    host_name_rect = host_name_surface.get_rect(center=host_pos)
                    screen.blit(host_name_surface, host_name_rect)

                    # Adjust local_int label position near the device
                    int_label_pos = (
                        start_pos[0],
                        start_pos[1] - 20  # Move above the device
                    )

                    # Render the local_int text
                    local_int_surface = font.render(local_int, True, (0, 0, 0))  # Black text
                    local_int_rect = local_int_surface.get_rect(center=int_label_pos)
                    screen.blit(local_int_surface, local_int_rect)

                    # Render the host_mac text
                    host_mac_surface = font.render(host_mac, True, (0, 0, 0))  # Black text
                    host_mac_rect = host_mac_surface.get_rect(center=(rect_positions[device][0], (rect_positions[device][1] - rect_height // 2 - 150)-30))
                    screen.blit(host_mac_surface, host_mac_rect)

        # Move the packet along the path
        target_pos = packet_path[path_index]
        dx, dy = target_pos[0] - packet_pos[0], target_pos[1] - packet_pos[1]
        dist = math.hypot(dx, dy)

        # Define starting position of the header_text_data
        txt_x, txt_y =(screen_width/2)-100, 400
        line_height = 20  # Height between lines

        if dist < packet_speed:  # Reached the current target
            packet_pos = list(target_pos)
            packet_pos_check = "(" + str(packet_pos).replace("[", "").replace("]", "") + ")"
            
            # Select the correct flow data based on direction
            flow_data = forward_flow_data if packet_path[0] == source_host_pos[source_host_name] else reverse_flow_data

            for item in flow_data:
                if str(item["packet_pos"]) == packet_pos_check:
                    headers_text_data = item["headers"]
                    pprint.pprint(headers_text_data)
                    
            path_index += 1
            if path_index >= len(packet_path):  # If it reached the last device, reverse direction
                packet_path.reverse()
                headers_text_data = ""
                path_index = 1
                
        else:
            packet_pos[0] += packet_speed * dx / dist
            packet_pos[1] += packet_speed * dy / dist
        
        # Draw the packet as a circle (green for outgoing, red for returning)
        packet_color = (0, 255, 0) if packet_path[0] == source_host_pos[source_host_name] else (255, 0, 0)
        pygame.draw.circle(screen, packet_color, (int(packet_pos[0]), int(packet_pos[1])), 10)

        # Render each line of data
        if headers_text_data != "":
            for key, value in headers_text_data.items():
                text = f'{key}: {value}'
                headers_text = font2.render(text, True, (0, 0, 0))
                screen.blit(headers_text, (txt_x, txt_y))
                txt_y += line_height
        else:
            text = ""
            headers_text = font2.render(text, True, (0, 0, 0))
            screen.blit(headers_text, (txt_x, txt_y))

        txt_y = 400

        # Update the display
        pygame.display.flip()

        # Cap the frame rate to 30 frames per second (you can reduce this to slow down the animation)
        clock.tick(30)  # Lower this number to slow down the animation further

    pygame.quit()

if __name__ == "__main__":
    main()