## Introduction
### What is Sweepy?
Sweepy is an internal network scanner and IP address sweeper built in Python, Sweepy will list all (pingable) hosts that are currently connected to the network of the host using the script.

### Why using Sweepy?
- Open source
- built using Python
- It's always good to know number of connected hosts along with their ip addresses
- Very useful in internal network penetration testing (especially scanning and enumeration phase)

### Modules
Sweepy utilizes a lot of modules and packages, but it requires three packages to be installed. More on that later (see [Installation below](#installation)):
- pyfiglet
- sys
- socket
- requests
- ipaddress (and ip_network)
- struct
- multprocessing (Process and Manager)
- subprocess
- os
- prettrytable (PrettyTable)

## Installation
### Cloning the repository
The code can be cloned using git tool. If you're confused, please watch [this video](https://www.youtube.com/watch?v=q9wc7hUrW8U) or simply copy and paste the code bellow in your shell:
```
git clone https://github.com/0xY43/sweepy.git
```

### Installing requirements
After cloning the repository to your local machine, you might notice the (requirements.txt) text file, which includes all the required modules to run the script. These requirements can be installed using pip. Please copy and paste the following code in your shell:
```bash
pip install -r requirements.txt
```

### Finally, running the script
Finally, after cloning the repository and installing the required modules, you can run the script. The command for running the script can vary depending on the shell you're using. Example:
```bash
python3 swee.py
```

## The Algorithm (Sweeper)

### Check for internet connectivity
At first, the tool will check for internet connectivity. If you're not connected to the internet it will ask you to connect and exit the script. The code behind it utilizes the `requests` module:
```python
# Checks if the device is connected to the internet or no
def check_internet_connection():
    try:
        response = requests.get("https://google.com")
        return True
    except requests.ConnectionError:
        return False

```

### Checking arguments
The script doesn't take any arguments at the moment, for that reason the `sys.argv` vector must equal to one only (the only argument is the script name itself):
```python
# Checks for the arguments, the script doesn't take any arguments for now
def check_arguments():
    if  (len(sys.argv) > 1 or len(sys.argv) < 1):
        print("Script doesn't take any argument")
        print("Syntax: python3 swee.py")
        sys.exit(0)
    else:
        return True
```

### Clear method
The clear method is used through out the whole script. It's used to remove all the previous output of the terminal:
```python
# Clears the output of the terminal
def clear():
    # Clearing all previous output
    if (os_type() == "linux"):
        os.system("clear")
    elif (os_type() == "windows"):
        os.system("cls")
    else:
        os.system("CLS")
```

### ASCII art method
The ASCII art method uses the `pyfiglet` module, the `pyfiglet` module is a requirement for the script to run. If you're confused please take a look at the [installating requirements section](#installing-requirements):
```python
# Prints ASCII art of the script name along with the credits
def ascii_art():
    print()
    text = pyfiglet.figlet_format("Swee.py", font="big")
    credit = "                      GitHub.com/0xY43"
    print(text)
    print(credit)
    print()
```

### Getting user input
The technique used for getting the **correct** input from the user is the `match case` in a `while(True)` loop:
```python
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

```
How ever, this technique is not good for **large range of input,** because it becomes very hard to do it manaully.
<br>
\
The second technique for larger range of input is the `try except` in a `while(True)` loop.

### IP sweep method
The first thing the algorithm does is getting the subnet mask from user, afterwards it will trigger a connection using the `socket` module to figure out the IP address of the user. From this information the IP address of the network can be figured out by logically ANDing the subnet mask and the IP address. <br>
\
Passing the network IP address to the `ipaddress.ip_network()` method will return an `IPv4Network` object, which has the `host()` method. The `host()` method will return all possible `IPv4` addresses in the network.
<br>
\
Afterwards, all hosts within the list will be pinged. The ones that respond will be formatted in a talbe using `prettrytable` module.
```python
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
```
