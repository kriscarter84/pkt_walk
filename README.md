Thank you for trying this code

1. download/clone .py and all the .gz files
2. open the .py file and cehck which input data you want to use:
   for vxlan:
    source_ip_addr = "10.10.10.10"
    source_mac_addr = "c474.86d1.c325" # 1 spine, 2 vteps
    destination_ip_addr = "20.20.20.20"
    destination_mac_addr = "c43e.48ac.6a92" # 1 spine, 2 vteps
   for non vxlan:
    source_ip_addr = "10.10.10.10"
    source_mac_addr = "0481.502e.563f" # 4 devices, no vxlan
    destination_ip_addr = "20.20.20.20"
    destination_mac_addr = "047f.ffca.1c55" # 4 devices, no vxlan
3. execute the code by:
   for vxlan:
     python3 main.py 3 spine1.log.gz vtep1.log.gz vtep2.log.gz
   for non vxlan:
     python3 main.py 4 A1.log.gz A2.log.gz A3.log.gz A4.log.gz


How does it work:
- code parses the show-tech files and stores the important data from mac address, arp, routing, vxlan tables
- it will then work out the device where the source and destination host is connected and compute the next hops
- it stores forward and reverse data into seperate dictionaries and uses them to plot and animate the packet walk
