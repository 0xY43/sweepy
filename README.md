## Introduction
### What is Sweepy?
Sweepy is an internal network scanner and IP address sweeper built in Python, Sweepy will list all (pingable) hosts that are currently connected to the network of the host using the script.

Please watch [this video](https://youtu.be/ohFFMTxaFmc) for detailed explanation.
>[!NOTE] PLEASE NOTE
>The demonstration shown in the video above is for the older version of Sweepy. The current version is a CLI tool that **almost guarantees** listing all hosts withing the network through doing multiple Nmap scans. 

### Why using Sweepy?
- Open source
- built using Python
- It's always good to know number of connected hosts along with their ip addresses
- Very useful in internal network penetration testing (especially scanning and enumeration phase)

### How does it work?
The script will run 15 Nmap host ICMP request discovery scans in parallel, each scan will scan the entire network and will list all the hosts that are currently connected to the network.

### Why not using normal Nmap?
Nmap is a great tool, but scanning the entire network is not the best way to find all the hosts that are currently connected. I have noticed the same problem occurs when using the built-in ping command. Due to protocol restrictions, these two tools do not list all connected hosts on the first scan. For this exact reason, I have created Sweepy to overcome this limitation (**for most of the time**).


### Modules
Sweepy utilizes a lot of modules and packages, but it requires certain packages to be installed. More on that later (see [Installation below](#installation)):
- nmap
- argparse
- sys
- socket
- requests
- threading
- ipaddress (and ip_network)
- struct
- prettrytable (PrettyTable)
- time

## Installation
### Cloning the repository
The code can be cloned using git tool. If you're confused, please watch [this video](https://www.youtube.com/watch?v=q9wc7hUrW8U) or simply copy and paste the code bellow in your shell:
```
git clone https://github.com/HexY43/sweepy.git
```

### Installing requirements
After cloning the repository to your local machine, you might notice the (requirements.txt) text file, which includes all the required modules to run the script. These requirements can be installed using pip. Please copy and paste the following code in your shell:
```bash
pip install -r requirements.txt
```

### Finally, running the script
Finally, after cloning the repository and installing the required modules, you can run the script. The command for running the script can vary depending on the shell you're using. Example:
```bash
python3 swee.py -r <subnet_mask>
```
