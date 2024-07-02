import ipaddress
import concurrent.futures
import subprocess
import json
import nmap 

banner = """
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗     ██╗   ██╗ ██████╗ 
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██║     ██║   ██║██╔════╝ 
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝██║     ██║   ██║██║  ███╗
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔═══╝ ██║     ██║   ██║██║   ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║     ███████╗╚██████╔╝╚██████╔╝
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝██╝     ╚══════╝ ╚═════╝  ╚═════╝ 
                                       ██████╝
 				      ████████╝
					█╝ █╝ 
                                                                           """

def ping_host(subnet):
    active_hosts = []
    try:
        # Esegui hostscan.py con l'opzione della subnet
        response = subprocess.run(['sudo', 'python3', 'hostscan.py', subnet], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        output = response.stdout.decode('utf-8').strip().splitlines()
        
        # Parsing dell'output per ottenere gli host attivi
        for line in output:
            if line.startswith('[+]'):
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[1]
                    active_hosts.append(ip)
        return active_hosts
    except subprocess.CalledProcessError as e:
        print(f"Errore durante il ping della sottorete {subnet}: {e}")
        return None

def trova_sottoreti_attive():
    try:
        output = subprocess.check_output(['python3', 'subnet.py']).decode('utf-8').strip()
        active_subnets = [line.strip() for line in output.splitlines() if line.strip()]
        return active_subnets
    except subprocess.CalledProcessError as e:
        print(f"Errore durante l'esecuzione di subnet.py: {e}")
        return None

def scan_ports_and_services(host):
    print(f"Eseguendo scansione delle porte su {host}")
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments='-sV -T3 -Pn -A -p-')

    scan_data = []
    if host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                service = nm[host][proto][port]
                service_info = {
                    "port": port,
                    "protocol": proto,
                    "state": service["state"],
                    "name": service["name"],
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "extra_info": service.get("extrainfo", "")
                }
                scan_data.append(service_info)
    return scan_data

def run_vulnerability_scan(host):
    try:
        result = subprocess.check_output(['python3', 'Vulnscan.py', host]).decode('utf-8').strip()
        print(f"Output grezzo da Vulnscan.py per {host}: {result}")
        
        if result:
            return json.loads(result)
        else:
            print(f"Nessun output ricevuto da Vulnscan.py per {host}.")
            return ["Nessun output ricevuto dalla scansione delle vulnerabilità"]
    except subprocess.CalledProcessError as e:
        print(f"Errore durante la scansione delle vulnerabilità su {host}: {e}")
        return ["Errore durante la scansione delle vulnerabilità"]
    except json.JSONDecodeError as e:
        print(f"Errore di decodifica JSON per {host}: {e}")
        return ["Errore di decodifica JSON durante la scansione delle vulnerabilità"]

def main():
    print(banner)
    subnet_attive = trova_sottoreti_attive()
    host_discovery_results = {}

    if subnet_attive:
        print("Sottoreti attive trovate:")
        for subnet in subnet_attive:
            print(f" - {subnet}")

        for subnet in subnet_attive:
            active_hosts = ping_host(subnet)
            if active_hosts:
                host_discovery_results[subnet] = active_hosts
                print(f"Host attivi trovati nella subnet {subnet}:")
                for host in active_hosts:
                    print(f" - {host}")
            else:
                print(f"Nessun host attivo trovato nella subnet {subnet}.")
            print()

        with open('host_discovery_results.json', 'w') as json_file:
            json.dump(host_discovery_results, json_file, indent=4)
    else:
        print("Nessuna sottorete attiva trovata.")
        return

    # Scansione delle porte e dei servizi per gli host attivi
    with open('host_discovery_results.json', 'r') as json_file:
        host_discovery_results = json.load(json_file)

    port_scan_results = {}
    vulnerabilities_results = {}

    for subnet, active_hosts in host_discovery_results.items():
        for host in active_hosts:
            port_scan_results[host] = scan_ports_and_services(host)
            vulnerabilities_results[host] = run_vulnerability_scan(host)

    # Salvataggio dei risultati della scansione delle porte in un file JSON
    with open('port_scan_results.json', 'w') as json_file:
        json.dump(port_scan_results, json_file, indent=4)

    # Salvataggio dei risultati della scansione delle vulnerabilità in un file JSON
    with open('vulnerabilities_results.json', 'w') as json_file:
        json.dump(vulnerabilities_results, json_file, indent=4)

    # Stampa dei risultati in formato leggibile
    print("\nRisultati della scansione delle porte:")
    for host, services in port_scan_results.items():
        print(f"\nHost: {host}")
        for service in services:
            print(service)

    print("\nRisultati della scansione delle porte salvati in 'port_scan_results.json'.")
    print("Risultati della scansione delle vulnerabilità salvati in 'vulnerabilities_results.json'.")

if __name__ == "__main__":
    main()
