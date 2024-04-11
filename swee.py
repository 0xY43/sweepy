#!/usr/bin/env python3

# Global imports
import pyfiglet
import sys
import socket
import requests
import ipaddress
from ipaddress import ip_network
import struct
import platform
from multiprocessing import Process, Manager
import subprocess
import os
from prettytable import PrettyTable


# CONSTANTS


# Global variables
flag = '-n' if platform.system().lower()=='windows' else '-c'
os_type = platform.system().lower


def main():
    # Check if the host is connected to the internet or not
    if(check_internet_connection()):
        # Check if arugments are true then continue to print ASCII art and let user make a choice
        check_arguments()
        clear()
        ascii_art()
        
        # Get choice from user and continue to execute it
        choice = user_choice()
        match choice:
            case "1":
                ip_sweep()
            case _:
                print("HOW DID NOT YOU SANITIZE INPUT IN THE FIRST PLACE?")
    else:
        print("Please make sure that you're connected to the internet!")






# Checks if the device is connected to the internet or no
def check_internet_connection():
    try:
        response = requests.get("https://google.com")
        return True
    except requests.ConnectionError:
        return False
    


# Checks for the arguments, the script doesn't take any arguments for now
def check_arguments():
    if  (len(sys.argv) > 1 or len(sys.argv) < 1):
        print("Script doesn't take any argument")
        print("Syntax: python3 swee.py")
        sys.exit(0)
    else:
        return True



# Prints ASCII art of the script name along with the credits
def ascii_art():
    print()
    text = pyfiglet.figlet_format("Swee.py", font="big")
    credit = "                      GitHub.com/HexY43"
    print(text)
    print(credit)
    print()


# Get choice from user and validate it (choice must be from the list)
def user_choice():
    print("Please make a choice:")
    print("[1] Internal IP sweep")
    print("[X] Exit the script")

    while(True):
        print()
        choice = input("Choice: ")
        match choice:
            case "1":
                return "1"
            case "X" | "x":
                sys.exit("Thank you for using the script!")
            case _:
                print("That is not a valid choice, please try again.")
                print()



# First choice [1]: Internal network IP sweep that lists all the connected alive hosts
def ip_sweep():
    clear()
    ascii_art()
    print()
    print("[1] Internal IP sweep")
    # Get subnet mask from user
    subnet_mask = get_subnet_mask_from_user()
    # Get the IP address of the user (as a str)
    str_ip = get_str_ip_address()
    # Conver str IP address to IPv4Address object
    ipv4_ip = convert_str_to_ipv4address_object(str_ip)
    # Get network IP address
    network_ip_address = get_network_ip(ipv4_ip, subnet_mask)
    # Get all pingable hosts in a list (as IPv4Address)
    list_of_hosts = get_all_hosts_as_IPv4Address(network_ip_address)
    # Convert these hosts to str in a tuple
    tuple_of_hosts = convert_ipv4_to_str(list_of_hosts)


    # Associated with ALGORITHM 1 in ping_and_add_alive_hosts()
    # with multiprocessing.Pool(CONCURRENCY) as k:
    #    k.map(ping_and_add_alive_hosts, y)
    
    # Multithreading the process of pinging all hosts and appending them to their corresponding list
    with Manager() as manager:
        alive_hosts = manager.list()
        dead_hosts = manager.list()
        processes = []
        for ip in tuple_of_hosts:
            p = Process(target=ping_and_add_alive_hosts, args=(alive_hosts, dead_hosts, ip))
            p.start()
            processes.append(p)
        for p in processes:
            p.join()
        alive_hosts = list(alive_hosts)
        dead_hosts = list(dead_hosts)
        
    # Print alive hosts list and show options of ip_sweep()
    results_and_options1(alive_hosts, dead_hosts)


# Prints the results and shows options of [1] (ip_sweep())
def results_and_options1(alive_hosts, dead_hosts):
    clear()
    ascii_art()

    # Print output as table
    length = len(alive_hosts)
    columns = ["Host"]
    table = PrettyTable()
    table.header = False
    table.title = f"Connected hosts ({length})"
    table.add_column(columns[0],alive_hosts)
    print(table)

    # Options
    print()
    print("Please make a choice:")
    print("[1] Export connected hosts to a text file")
    print("[X] Exit the script")
    print()
    while(True):
        match input("Choice: "):
            case "1":
                with open("Internal sweep.txt", "w") as file:
                    for ip in alive_hosts:
                        file.write(str(ip) + "\n")
                print()
                print("Done!")
                sys.exit("Thank you for using the script!")
            case "X" | "x":
                sys.exit("Thank you for using the script!")
            case _:
                print("That is not a valid choice, please try again.")
    


# Validates user input (validate subnet mask)
def get_subnet_mask_from_user():
    while(True):
        try:
            subnet_mask = int(input("Subnet mask: "))
            if not 0 <= subnet_mask < 33:
                print("subnet mask value is between [0,32] !")
                print("Example - Subnetmask: 24")
                print()
            else:
                return subnet_mask
        except ValueError:
            print("subnet mask is an integer value, please try again!")
            print()


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


# Ping all hosts and capture alive ones
def ping_and_add_alive_hosts(alive_hosts, dead_hosts, ip):

    # ALGORITHM 1
    #desired_path = str(pathlib.Path(__file__).parent.resolve()) + "/pings"
    #if not os.path.exists(desired_path):
    #    os.makedirs(desired_path)
    #for ip in ip_list:
    #    response = os.system(f"ping {flag} 1 {ip} > {desired_path}/{ip}.txt")
    #    if (response == 0):
    #        alive_hosts.append(ip)
    #    else:
    #        dead_hosts.append(ip)

    # ALGORITHM 2
    response = subprocess.call(["ping", "-w", "1450",f"{flag}", "1", ip], stdout=subprocess.DEVNULL)
    if (response == 0):
        #print(f"{ip} is alive :D")
        alive_hosts.append(ip)
    else:
        #print(f"{ip} is dead D:")
        dead_hosts.append(ip)


# Clears the output of the terminal
def clear():
    # Clearing all previous output
    if (os_type() == "linux"):
        os.system("clear")
    elif (os_type() == "windows"):
        os.system("cls")
    else:
        os.system("CLS")



if __name__ == "__main__":
    main()
    
