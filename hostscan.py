import nmap
import sys
import socket
from colorama import Fore, Style, init
import multiprocessing
import argparse

init(autoreset=True)
scanner = nmap.PortScanner()

def scanStatus(host, inputed):
    try:
        scanner.scan(host, '1', '-v -sT')
        if scanner[host].state() == 'up':
            print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Status: {host} is {Fore.GREEN}{scanner[host].state()}{Style.RESET_ALL}.')
        else:
            print(f'[{Fore.YELLOW}?{Style.RESET_ALL}] Status: {host} is {Fore.RED}{scanner[host].state()}{Style.RESET_ALL}.')
            sys.exit()
    except KeyboardInterrupt:
        sys.exit('\n^C\n')
    except Exception as e:
        print(f'[{Fore.RED}!{Style.RESET_ALL}] Error: {Fore.RED}{e}{Style.RESET_ALL}')
        sys.exit(1)

def scan(host, inputed, prstart, prend, scantype):
    scanStatus(host, inputed)
    print('Scan will start. Press CTRL-C to cancel.')

    try:
        print(f'[{Fore.YELLOW}?{Style.RESET_ALL}] Scanning {Fore.YELLOW}{host}{Style.RESET_ALL}:{prstart}-{prend}...')
        scanner.scan(host, f'{prstart}-{prend}', f'-v {scantype}')
    except KeyboardInterrupt:
        sys.exit('\n^C\n')
    except Exception as e:
        print(f'[{Fore.RED}!{Style.RESET_ALL}] Error: {Fore.RED}{e}{Style.RESET_ALL}')
    else:
        if len(scanner[host].all_protocols()) == 0:
            print(f'[{Fore.RED}!{Style.RESET_ALL}] {Fore.RED}No port(s) found.{Style.RESET_ALL}')
        else:
            for protocol in scanner[host].all_protocols():
                if scanner[host][protocol].keys():
                    print(f'\nProtocol: {protocol.upper()}')
                    print('\n PORT     \t\tSTATE     \t\tSERVICE')
                    for port in scanner[host][protocol].keys():
                        print(f" {Fore.GREEN}{port}{Style.RESET_ALL}      \t\t{scanner[host][protocol][port]['state']}       \t\t{scanner[host][protocol][port]['name']}")

def scanWithPort(host, inputed, int, i, j, scantype):
    try:
        if j == 0:
            scanStatus(host, inputed)
            print(f'[{Fore.YELLOW}?{Style.RESET_ALL}] Scanning {Fore.YELLOW}{host}{Style.RESET_ALL}')
            print('Scan will start. Press CTRL-C to cancel.')
        scanner.scan(host, f'{int}', f'-v {scantype}')
    except KeyboardInterrupt:
        sys.exit('^C\n')
    except Exception as e:
        print(f'[{Fore.RED}!{Style.RESET_ALL}] Error: {Fore.RED}{e}{Style.RESET_ALL}')
    else:
        for protocol in scanner[host].all_protocols():
            if scanner[host][protocol].keys():
                if j == 0:
                    print(f'Protocol: {protocol.upper()}')
                    print('\n PORT     \t\tSTATE     \t\tSERVICE')
                for port in scanner[host][protocol].keys():
                    print(f" {Fore.GREEN}{port}{Style.RESET_ALL}      \t\t{scanner[host][protocol][port]['state']}       \t\t{scanner[host][protocol][port]['name']}")

def scanLocalDevices(network):
    print(f'The network address is {network}')

    try:
        print(f'[{Fore.YELLOW}?{Style.RESET_ALL}] Scanning for devices on {Fore.YELLOW}{network}{Style.RESET_ALL} network...')
        scanner.scan(hosts=network, arguments='-v -sn')
    except KeyboardInterrupt:
        sys.exit('\n^C\n')
    except Exception as e:
        print(f'[{Fore.RED}!{Style.RESET_ALL}] Error: {Fore.RED}{e}{Style.RESET_ALL}')
    else:
        for host in scanner.all_hosts():
            if scanner[host]['status']['state'] == 'up':
                try:
                    if len(scanner[host]['vendor']) == 0:
                        try:
                            print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {host}      \t {socket.gethostbyaddr(host)[0]}")
                        except:
                            print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {host}")
                    else:
                        try:
                            print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {host}      \t {scanner[host]['vendor']}      \t {socket.gethostbyaddr(host)[0]}")
                        except:
                            print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {host}      \t {scanner[host]['vendor']}")
                except:
                    print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {host}      \t {scanner[host]['vendor']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('subnet', type=str, help='The subnet to scan (e.g., 192.168.1.0/24)')
    args = parser.parse_args()

    subnet = args.subnet
    scanLocalDevices(subnet)
