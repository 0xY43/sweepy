
#!/usr/bin/env python3

# Global imports
import nmap
import argparse
import sys
import socket
import requests
import threading
import ipaddress
from ipaddress import ip_network
import struct
from prettytable import PrettyTable
import time

# GLOBAL VARIABLE:
list_of_hosts = []


def main():

    
    # Check if the host is connected to the internet or not
    if(check_internet_connection()):

        # Required arguments: -s or --subnet-mask (subnet mask)
        args = parse_args()
        validate_subnet_mask(args.s)
        
        

        # Get network information
        network_address = get_network_information(args.s)[0]
        

        # Using mutli-threaded nmap scans to sweep and scan all hosts in the network
        start = time.time()
        t1 = threading.Thread(target=nmap_scan, args=(network_address,list_of_hosts))
        t1.start()
        t2 = threading.Thread(target=nmap_scan, args=(network_address,list_of_hosts))
        t2.start()
        t3 = threading.Thread(target=nmap_scan, args=(network_address,list_of_hosts))
        t3.start()
        t4 = threading.Thread(target=nmap_scan, args=(network_address,list_of_hosts))
        t4.start()
        t5 = threading.Thread(target=nmap_scan, args=(network_address,list_of_hosts))
        t5.start()
        t6 = threading.Thread(target=nmap_scan, args=(network_address,list_of_hosts))
        t6.start()
        t7 = threading.Thread(target=nmap_scan, args=(network_address,list_of_hosts))
        t7.start()
        t8 = threading.Thread(target=nmap_scan, args=(network_address,list_of_hosts))
        t8.start()
        t9 = threading.Thread(target=nmap_scan, args=(network_address,list_of_hosts))
        t9.start()
        t10 = threading.Thread(target=nmap_scan, args=(network_address,list_of_hosts))
        t10.start()
        t11 = threading.Thread(target=nmap_scan, args=(network_address,list_of_hosts))
        t11.start()
        t12 = threading.Thread(target=nmap_scan, args=(network_address,list_of_hosts))
        t12.start()
        t13 = threading.Thread(target=nmap_scan, args=(network_address,list_of_hosts))
        t13.start()
        t14 = threading.Thread(target=nmap_scan, args=(network_address,list_of_hosts))
        t14.start()
        t15 = threading.Thread(target=nmap_scan, args=(network_address,list_of_hosts))
        t15.start()
        t1.join()
        t2.join()
        t3.join()
        t4.join()
        t5.join()
        t6.join()
        t7.join()
        t8.join()
        t9.join()
        t10.join()
        t11.join()
        t12.join()
        t13.join()
        t14.join()
        t15.join()

        
        # Format hosts
        number_of_scans = 15
        format_list(list_of_hosts)
        end = time.time()
        rounded_time = round(end - start, 2)
        print(f"The script has completed {number_of_scans} Nmap host ICMP request discovery scans for the whole network")
        print(f"Time taken to complete the scans: {rounded_time} seconds")
        

    else:
        print("Please make sure that you're connected to the internet!")
        sys.exit(0)


def parse_args():

    parser = argparse.ArgumentParser(
        prog="swee.py",
        description="A simple script to perform internal network IP sweep",
        epilog="https://github.com/HexY43/Swee.py",
    )

    parser.add_argument("-s", type=int, help="Subnet mask (Range: [0,32])", required=True)
    args = parser.parse_args()
    return args


def validate_subnet_mask(subnet_mask):
    if not 0 <= subnet_mask < 33:
        print("Subnet mask value is between [0,32] !")
        print("Example: swee.py -s 24")
        sys.exit(0)
    else:
        return subnet_mask


# Checks if the device is connected to the internet or no
def check_internet_connection():
    try:
        response = requests.get("https://google.com")
        return True
    except requests.ConnectionError:
        return False
         

def get_network_information(subnet_mask):

    str_ipv4 = get_str_ip_address()
    ipv4_ip_object = convert_str_to_ipv4address_object(str_ipv4)
    network_address = get_network_ip(ipv4_ip_object, subnet_mask)
    network_address_str = format(network_address)
    return [network_address_str]


# Fetches the IP address of the host running the script
def get_str_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 443))
    str_ip = (s.getsockname()[0])
    return str_ip


# Convert 'str' object to 'IPV4Address' object
def convert_str_to_ipv4address_object(ipv4):
    ipv4_ip = ipaddress.ip_address(ipv4)
    return ipv4_ip


# Get network IP address
def get_network_ip(ip, subnet_mask_prefix):
    subnet_mask_dotted_decimal = get_subnet_mask_dotted_decimal(subnet_mask_prefix)
    mask = int(ipaddress.ip_address(subnet_mask_dotted_decimal))
    address = ipaddress.ip_address(int(ip) & mask)
    network_address = ipaddress.ip_network(f"{address}/{subnet_mask_prefix}")
    return network_address
    

# Get the subnet mask as dotted decimal notation
def get_subnet_mask_dotted_decimal(subnet_mask_prefix):
    host_bits = 32 - subnet_mask_prefix
    subnet_mask_dotted_decimal = socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))
    return subnet_mask_dotted_decimal


# Get list of hosts in the network (as IPv4 objects)
def get_all_hosts_as_IPv4Address(network_address):
    ip_ipv4_list = list(ip_network(network_address).hosts())
    return ip_ipv4_list


# Convert all IPs from IPv4 object to str object
def convert_ipv4_to_str(ip_ipv4_list):
    ip_str_list = []
    for ip in ip_ipv4_list:
        ip_str_list.append(str(ip))
    ip_str_tuple = tuple(ip_str_list)
    return ip_str_tuple


# Nmap Scan function
def nmap_scan(network_address,list_of_hosts):
    # start = time.time()
    # nm = nmap.PortScanner()
    # hosts_list = []
    # number_of_scans = 5
    # for i in range(number_of_scans):
    #     nm.scan(hosts=network_address, arguments="-sn -PE")
    #     for x in nm.all_hosts():
    #         if x not in hosts_list:
    #             hosts_list.append(x)
    
    nm = nmap.PortScanner()
    nm.scan(hosts=network_address, arguments="-sn -PE")
    for x in nm.all_hosts():
        if x not in list_of_hosts:
            list_of_hosts.append(x)
    return list_of_hosts


# Format hosts
def format_list(hosts_list_set):
    length = len(hosts_list_set)
    columns = ["Host"]
    table = PrettyTable()
    table.header = False
    table.title = f"Connected hosts ({length})"
    table.add_column(columns[0],hosts_list_set)
    print(f"{table}")


if __name__ == "__main__":
    main()
    
