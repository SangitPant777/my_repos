Python Network Cyber Tool Documentation
Introduction
The Python Network Cyber Tool is a versatile command-line utility designed to perform various network-related tasks such as port scanning, DNS lookup, ping testing, reverse DNS lookup, WHOIS lookup, and Shodan search. It provides a convenient interface for conducting these operations on specified targets.

Features
Port Scanning: Scan for open ports on a target host within a specified range of ports.
DNS Lookup: Resolve the IP address of a hostname using DNS.
Ping Test: Check the reachability of a host using ICMP echo requests.
Reverse DNS Lookup: Find the hostname associated with a given IP address.
WHOIS Lookup: Retrieve registration information for a domain using WHOIS.
Shodan Search: Perform a search on Shodan, a search engine for internet-connected devices.
Dependencies
Python 3.x
pyfiglet: For ASCII art banner generation.
whois: For WHOIS lookup functionality.
shodan: For Shodan search functionality.
Installation
Ensure that Python 3.x is installed on your system. Install the required dependencies using pip:

bash
Copy code
pip install pyfiglet whois shodan
Usage
Running the Tool: Execute the Python script (cyber_tool.py) in a terminal or command prompt.

bash
Copy code
python cyber_tool.py
Input: Enter the target(s) separated by space when prompted. To exit the tool, type "exit" and press Enter.

Output: The tool performs various network operations for each target entered and displays the results in the console.

Functions
print_section(title)

Description: Print a formatted section title.
Parameters:
title: Title of the section.
port_scan(target_host, start_port, end_port)

Description: Scan for open ports on a target host within a specified range.
Parameters:
target_host: Hostname or IP address of the target.
start_port: Starting port number of the range.
end_port: Ending port number of the range.
get_service_name(port)

Description: Get the name of the service associated with a port.
Parameters:
port: Port number.
dns_lookup(hostname)

Description: Perform DNS lookup to resolve the IP address of a hostname.
Parameters:
hostname: Hostname to lookup.
ping(hostname)

Description: Send ICMP echo requests to check host reachability.
Parameters:
hostname: Hostname or IP address to ping.
reverse_dns_lookup(ip_address)

Description: Perform reverse DNS lookup to find the hostname associated with an IP address.
Parameters:
ip_address: IP address to lookup.
whois_lookup(domain)

Description: Perform WHOIS lookup to retrieve domain registration information.
Parameters:
domain: Domain name to lookup.
shodan_search(query)

Description: Perform a search on Shodan using the specified query.
Parameters:
query: Query string for the search.
License
This tool is distributed under the MIT License. See LICENSE for details.

Acknowledgments
The Python Network Cyber Tool was created by [Author's Name] and is maintained by [Maintainer's Name].

Support
For questions, bug reports, or feature requests, please contact [Maintainer's Email].

Contributing
Contributions are welcome! Please fork the repository, make your changes, and submit a pull request.

Disclaimer
This tool is provided for educational and informational purposes only. Use it responsibly and at your own risk. The authors and maintainers are not responsible for any misuse or damage caused by the tool.

Version History
v1.0.0 (Date): Initial release.
