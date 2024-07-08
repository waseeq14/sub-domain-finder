import json
import argparse
from argparse import RawTextHelpFormatter
import re
import os
import dns.resolver
import requests
from queue import Queue
import pyfiglet

API_FILE = './api.json'
REQUIRED_APIS = ['virustotal', 'securitytrails']
api_keys = None


def initialize_api_keys():
    global api_keys
    api_keys = load_api_keys()

def load_api_keys():
    if not os.path.exists(API_FILE):
        print(f"Config file does not exist. Initializing with empty keys.\n")
        return {}

    try:
        with open(API_FILE, 'r') as file:
            config = json.load(file)
    except json.JSONDecodeError:
        return {}

    return config

def save_api_keys(api_keys):
    with open(API_FILE, 'w') as file:
        json.dump(api_keys, file, indent=4)

def set_api_key(service_name):
    api_keys = load_api_keys()
    current_api_key = api_keys.get(service_name)

    if current_api_key:
        replace = input(f"An API key for {service_name} is already set. Do you want to replace it? (Y/N): ")
        if replace.strip().lower() != 'y':
            print(f"Keeping the existing API key for {service_name}.\n")
            return
    
    api_key = input(f"Enter your API key for {service_name}: ")

    if not validate_api_key(api_key):
        print(f"Invalid API key format for {service_name}. API key must match the required format.\n")
        return
    
    api_keys[service_name] = api_key
    save_api_keys(api_keys)
    print(f"API key for {service_name} has been set.\n")

def validate_api_key(api_key):
    pattern = r'^[a-zA-Z0-9_-]{30,}$'
    return re.match(pattern, api_key) is not None

def clear_api_keys():
    try:
        with open(API_FILE, 'r') as file:
            api_keys = json.load(file)
    except FileNotFoundError:
        api_keys = {}  
    
    print("Current API keys:")
    any_keys_set = False
    
    for service, api_key in api_keys.items():
        if api_key:
            any_keys_set = True
        print(f"- {service}: {'Set' if api_key else 'Not set'}")
    
    if not any_keys_set:
        print("\nNone of the API keys have been set.")
        return
    
    choice = input("\nDo you want to clear all API keys? (Y/N): ").strip().lower()
    
    if choice == 'y':
        for service in api_keys:
            api_keys[service] = None
        save_api_keys(api_keys)
        print("All API keys have been cleared.")
    elif choice == 'n':
        for service in api_keys:
            if api_keys[service]:
                confirm = input(f"Do you want to remove {service} API key? (Y/N): ").strip().lower()
                
                if confirm == 'y':
                    api_keys[service] = None
                    print(f"{service} API key has been cleared.")
                elif confirm == 'n':
                    print(f"{service} API key was not cleared.")
                else:
                    print("Invalid input. Please enter Y or N.")
            else:
                print(f"No API key found for {service}. Skipping...")
        
        save_api_keys(api_keys)
    else:
        print("Invalid input. Please enter Y or N.")

def print_api_keys():
    api_keys = load_api_keys()
    if not api_keys:
        print("No API keys set. Use the API key manager to set them.\n")
    else:
        print("Currently set API keys:")
        for service_name, api_key in api_keys.items():
            print(f"{service_name}: {api_key}")


def subdomain_enum(domain, wordlist, output_file=None):
    output = []
    print(f"Sub-domain Enumeration for {domain}")
    subdomains = []
    with open(wordlist, 'r') as file:
        subdomains = file.read().splitlines()
    
    for subdomain in subdomains:
        try:
            full_domain = f"{subdomain}.{domain}"
            result = dns.resolver.resolve(full_domain, 'A')
            for ipval in result:
                output_line = f'{full_domain} | {ipval.to_text()}'
                output.append(output_line)
                print(output_line)
        except:
            pass

    if output_file:
        with open(output_file, 'a') as f:
            for line in output:
                f.write(line + '\n')

def fetch_subdomains_from_virustotal(domain, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        subdomains = {item['id'] for item in data['data']}
        return subdomains
    else:
        print(f"\nError fetching from VirusTotal: {response.status_code} {response.text}")
        return set()

def fetch_subdomains_from_dnsdumpster(domain):
    url = "https://api.hackertarget.com/hostsearch/?q=" + domain
    response = requests.get(url)
    
    if response.status_code == 200:
        subdomains = {line.split(',')[0] for line in response.text.splitlines()}
        return subdomains
    else:
        print(f"\nError fetching from DNSDumpster: {response.status_code} {response.text}")
        return set()

def fetch_subdomains_from_securitytrails(domain, api_key):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {
        "APIKEY": api_key
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        subdomains = {f"{sub}.{domain}" for sub in data['subdomains']}
        return subdomains
    else:
        print(f"\nError fetching from SecurityTrails: {response.status_code} {response.text}")
        return set()

def recursive_subdomain_discovery(domain, api_keys, depth, api_key_checked=None):
    if api_key_checked is None:
        api_key_checked = {
            'virustotal': False,
            'securitytrails': False
        }
    
    discovered_subdomains = {
        'virustotal': set(),
        'dnsdumpster': set(),
        'securitytrails': set()
    }
    queue = Queue()
    queue.put(domain)
    seen = set()
    
    while not queue.empty() and depth > 0:
        current_domain = queue.get()
        if current_domain in seen:
            continue
        seen.add(current_domain)
        
        if not api_key_checked['virustotal']:
            api_key_virustotal = api_keys.get('virustotal')
            if api_key_virustotal:
                subdomains = fetch_subdomains_from_virustotal(current_domain, api_key_virustotal)
                discovered_subdomains['virustotal'].update(subdomains)
        
        # Fetch subdomains from DNSDumpster
        subdomains = fetch_subdomains_from_dnsdumpster(current_domain)
        discovered_subdomains['dnsdumpster'].update(subdomains)
        
        if not api_key_checked['securitytrails']:
            api_key_securitytrails = api_keys.get('securitytrails')
            if api_key_securitytrails:
                subdomains = fetch_subdomains_from_securitytrails(current_domain, api_key_securitytrails)
                discovered_subdomains['securitytrails'].update(subdomains)
        
        for subdomain in subdomains:
            queue.put(subdomain)
        
        depth -= 1

    return discovered_subdomains

def print_subdomain_discovery_by_api(domain, api_keys, depth, output_file=None):
    discovered_subdomains = recursive_subdomain_discovery(domain, api_keys, depth)

    print("\nDiscovered Subdomains:")

    print("\nFrom VirusTotal:")
    if not api_keys.get('virustotal'):
        print("  The API key has not been set for VirusTotal.")
    else:
        for subdomain in discovered_subdomains['virustotal']:
            print(f"  - {subdomain}")

    print("\nFrom DNSDumpster:")
    for subdomain in discovered_subdomains['dnsdumpster']:
        print(f"  - {subdomain}")

    print("\nFrom SecurityTrails:")
    if not api_keys.get('securitytrails'):
        print("  The API key has not been set for SecurityTrails.")
    else:
        for subdomain in discovered_subdomains['securitytrails']:
            print(f"  - {subdomain}")

    # Write to output file if specified
    if output_file:
        with open(output_file, 'a') as f:
            f.write("\nDiscovered Subdomains:\n\n")
            
            f.write("From VirusTotal:\n")
            if not api_keys.get('virustotal'):
                f.write("  The API key has not been set for VirusTotal.\n")
            else:
                for subdomain in discovered_subdomains['virustotal']:
                    f.write(f"  - {subdomain}\n")
            
            f.write("\nFrom DNSDumpster:\n")
            for subdomain in discovered_subdomains['dnsdumpster']:
                f.write(f"  - {subdomain}\n")
            
            f.write("\nFrom SecurityTrails:\n")
            if not api_keys.get('securitytrails'):
                f.write("  The API key has not been set for SecurityTrails.\n")
            else:
                for subdomain in discovered_subdomains['securitytrails']:
                    f.write(f"  - {subdomain}\n")

def print_banner():
    banner = pyfiglet.figlet_format("Sub Domain Finder")
    print(banner)

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="Web Information Gathering Tool",
        formatter_class=RawTextHelpFormatter,
        epilog="""\
Depth is Optional if you want to set it. The defualt value is set as 2.
        
Argument requirements for each choice:
  1. Sub-domain Enumeration Using Wordlist:     --domain, --wordlist
  2. Sub-domain Enumeration Using API:          --domain, --depth (Optional Arg)
        """
    )
    parser.add_argument('--domain', type=str, help='The domain to gather information about')
    parser.add_argument('--wordlist', type=str, help='The wordlist file for sub-domain and directory enumeration')
    parser.add_argument('--output', type=str, help='The file to save the output')
    parser.add_argument('--setapi', action='store_true', help="Set API key for the services")
    parser.add_argument('--getapi', action='store_true', help="Print currently set API keys")
    parser.add_argument('--clearapi', action='store_true', help="Removes currently set API keys")
    parser.add_argument('--depth', type=int, default=2, help='Depth for recursive subdomain discovery')

    args = parser.parse_args()

    menu = """
    Please select an option:
    1. Sub-domain Enumeration Using Wordlist
    2. Sub-domain Enumeration Using API
    3. Exit
    """

    if args.setapi:
        for service_name in REQUIRED_APIS:
            set_api_key(service_name)
    elif args.getapi:
        print_api_keys()
    elif args.clearapi:
        clear_api_keys()
    else:
        while True:
            initialize_api_keys()
            print(menu)
            choice = input("Enter your choice: ")
            if choice == '1':
                if args.domain:
                    if not args.wordlist:
                        print("Please provide a wordlist for sub-domain enumeration")
                    else:
                        subdomain_enum(args.domain, args.wordlist, args.output)
                else:
                    print("Please provide a domain using --domain option")
            elif choice == '2':
                if args.domain:
                    print_subdomain_discovery_by_api(args.domain, api_keys, args.depth, args.output)
                else:
                    print("Please provide a domain using --domain option")
            elif choice == '3':
                break
            else:
                print("Invalid choice, please try again")

if __name__ == "__main__":
    main()