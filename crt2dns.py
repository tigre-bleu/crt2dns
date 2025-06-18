#!/bin/env python3

import argparse
import json
import xml.etree.ElementTree as ET
import os
import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from multiprocessing.pool import ThreadPool
from alive_progress import alive_bar
from colorama import Fore

parser = argparse.ArgumentParser(description='Find DNS subdomains from TLS certificates')
parser.add_argument('-f', '--format', help='Input file format \nxml: Nmap XML\nhostport: one line per host:port)', default='xml')
parser.add_argument('-o', '--output', help='File output')
parser.add_argument('--timeout', help='Timeout when establishing connection (in seconds, default=5)', default=5)
parser.add_argument("-v", "--verbose", help="Show verbose output", action="store_true")
parser.add_argument("-q", "--quiet", help="Only show results", action="store_true")
parser.add_argument('-t', '--threads', help='Number of threads to run (default=5)', default=5)
parser.add_argument('files', help='Files to push', nargs='+')

args = parser.parse_args()

if args.verbose and args.quiet:
    print(Fore.RED, '[!] Cannot use verbose and quiet flags together')
    exit()

def print_verbose(text):
    if args.verbose:
        print(Fore.LIGHTBLACK_EX, text, Fore.RESET)
        
def print_not_quiet(*data):
    if not args.quiet:
        print(*data)

def nmap_xml_to_hostports(f):
    print_verbose(f"Parsing nmap xml from {f}")
    hostports = []
    tree = ET.parse(f)
    root = tree.getroot()
    for host in root.findall('host'):
        state = host.find('status').get("state")
        address = host.find('address[@addrtype="ipv4"]')
        if address is not None:
            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    state = port.find('state')
                    if state is not None and port.get("protocol") == 'tcp':
                        print_verbose(f'{address.get("addr")}:{port.get("portid")}')
                        hostports.append(f'{address.get("addr")}:{port.get("portid")}')
    return hostports

tls_endpoints = []
if args.format == 'xml':
    for f in args.files:
        for new_endpoint in nmap_xml_to_hostports(f):
            tls_endpoints.append(new_endpoint)
elif args.format == 'hostport':
    for f in args.files:
        with open(f, 'r') as lines:
            for line in lines:
                tls_endpoints.append(line)
else:
    print(Fore.RED, f"Error: {args.format} is not a valid choice")
    exit()

def scan(input):
    (host, port) = input

    print_verbose(f"[-] Starting thread for {host}:{port}")
    
    found_hostnames = []

    try:
        # Create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(args.timeout)
    
        # Wrap the socket with SSL/TLS
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Disable certificate verification for this example

        ssl_sock = context.wrap_socket(sock, server_hostname=host)
   
        # Connect to the host and port
        ssl_sock.connect((host, int(port)))
    
        # Get the peer certificate
        der_cert = ssl_sock.getpeercert(binary_form=True)
        ssl_sock.close()
   
        # Parse the certificate
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
    
        # Extract the subject
        subject = cert.subject.rfc4514_string()
        found_hostnames.append(subject)
    
        # Extract the subjectAltName
        for extension in cert.extensions:
            if extension.oid == x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                subject_alt_name_extension = extension.value
                for name in subject_alt_name_extension.get_values_for_type(x509.DNSName):
                    found_hostnames.append(name)

    except TimeoutError as e:
        print_not_quiet(Fore.YELLOW, f'[!] Timeout while connecting to {host}:{port} ({e})', Fore.RESET)
    except ssl.SSLError as e:
        print_not_quiet(Fore.YELLOW, f'[!] SSL handshake error while connecting to {host}:{port} ({e})', Fore.RESET)
    except ConnectionRefusedError as e:
        print_not_quiet(Fore.YELLOW, f'[!] Connection refused while connecting to {host}:{port} ({e})', Fore.RESET)
    except ConnectionResetError as e:
        print_not_quiet(Fore.YELLOW, f'[!] Connection reset while connecting to {host}:{port} ({e})', Fore.RESET)
    except Exception as e:
        print_not_quiet(Fore.YELLOW, f'[!] Unexpected error while connecting to {host}:{port} ({e})', Fore.RESET)

    result = {
            'hostnames': found_hostnames,
            'ip': host,
            'port': port
            }
    return result

print_not_quiet(Fore.CYAN, f"[+] Testing {len(tls_endpoints)} endpoints")

hostnames = []
with alive_bar(len(tls_endpoints), title='Scanning', enrich_print=False) as bar:
    with ThreadPool(processes=int(args.threads)) as pool:
        scans_input_list = []
        for endpoint in tls_endpoints:
            (host, port) = endpoint.split(":")
            scans_input_list.append((host, port.rstrip()))
            
        for result in pool.imap(scan, scans_input_list):
            bar()
            
            new_hostnames = result['hostnames']
            ip = result['ip']
            port = result['port']
            for new_hostname in new_hostnames:
                if new_hostname not in hostnames:
                    print(Fore.GREEN, f'[*] {new_hostname}', Fore.RESET, f'{ip}:{port}')
                    hostnames.append(new_hostname)

    print(Fore.CYAN, f'[+] {len(hostnames)} items found', Fore.RESET)
    
    if args.output:
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        fp = open(args.output, 'w') 
        for hostname in hostnames:
            fp.write(f'hostname\n')
        fp.close()
        print_not_quiet(Fore.CYAN, f'[+] Result saved in {args.output}', Fore.RESET)
        
    bar.title('Scan finished')
