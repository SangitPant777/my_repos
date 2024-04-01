import socket
import subprocess
import sys
import pyfiglet
import whois
import shodan

def print_section(title):
    line = "*" * 40
    print("\n" + line)
    print(title.center(40, " "))
    print(line)

def port_scan(target_host, start_port, end_port):
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"Hostname {target_host} could not be resolved.")
        return

    open_ports = []
    print("Scanning target:", target_ip)
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    
    if open_ports:
        print_section("Open Ports for " + target_host)
        for port in open_ports:
            service_name = get_service_name(port)
            if service_name:
                print(f"Port: {port} ({service_name})")
            else:
                print(f"Port: {port}")
    else:
        print_section("No Open Ports for " + target_host)

def get_service_name(port):
    services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
    }
    return services.get(port)

def dns_lookup(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        print_section("DNS Lookup for " + hostname)
        print(f"IP Address: {ip_address}")
    except socket.gaierror:
        print_section("DNS Lookup for " + hostname)
        print(f"Hostname {hostname} could not be resolved.")

def ping(hostname):
    try:
        subprocess.check_call(['ping', '-n', '1', hostname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print_section("Ping Result for " + hostname)
        print(f"{hostname} is reachable.")
    except subprocess.CalledProcessError:
        print_section("Ping Result for " + hostname)
        print(f"{hostname} is unreachable.")

def reverse_dns_lookup(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)
        print_section("Reverse DNS Lookup for " + ip_address)
        print(f"Hostname: {hostname[0]}")
    except socket.herror:
        print_section("Reverse DNS Lookup for " + ip_address)
        print("Reverse DNS lookup failed.")

def whois_lookup(domain):
    print_section("WHOIS Lookup for " + domain)
    try:
        w = whois.whois(domain)
        print(f"Registrant: {w.get('registrant_name', 'Not available')}")
        print(f"Organization: {w.get('org', 'Not available')}")
    except Exception as e:
        print(f"Error: {e}")

def shodan_search(query):
    try:
        api_key = "Your Shodan API Key"
        api = shodan.Shodan(api_key)
        results = api.search(query)
        print_section("Shodan Search Results for " + query)
        for result in results['matches']:
            print(f"IP: {result['ip_str']}")
            print(f"Port: {result['port']}")
            print(f"Hostname: {result.get('hostnames', 'N/A')}")
            print(f"Organization: {result.get('org', 'N/A')}")
            print()
    except shodan.APIError as e:
        if e.value == '403 Forbidden':
            print("Error: Access denied. Please check your Shodan API key and ensure it has the necessary permissions.")
        else:
            print(f"Error: {e}")

if __name__ == "__main__":
    banner = pyfiglet.figlet_format("Cyber Tool", font="slant")
    print(banner)

    while True:
        targets = input("Enter target(s) separated by space (or 'exit' to quit): ").split()
        if 'exit' in targets:
            sys.exit(0)

        for target in targets:
            print()
            port_scan(target, 79, 81)
            dns_lookup(target)
            ping(target)
            try:
                ip_address = socket.gethostbyname(target)
                reverse_dns_lookup(ip_address)
                whois_lookup(target)
            except socket.gaierror:
                print("Reverse DNS and WHOIS lookup skipped as hostname could not be resolved.")
            except Exception as e:
                print(f"Error: {e}")

            # Shodan search for the target
            shodan_search(target)
