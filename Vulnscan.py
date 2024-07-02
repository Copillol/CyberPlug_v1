import sys
import subprocess
import re
import json

def scan_ip(ip_address):
    command = f"sudo nmap -sV --script vulners --script-args mincvss=6.0 {ip_address}"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr}")
        return None

def extract_exploit_vulnerabilities(scan_results):
    vulnerabilities = {}
    
    lines = scan_results.splitlines()
    current_port = None
    
    for line in lines:
        if "*EXPLOIT*" in line:
            if current_port is not None:
                vulnerabilities[current_port]["vulnerabilities"].append(extract_vulnerability_info(line))
        elif "/tcp" in line or "/udp" in line or "/sctp" in line:
            current_port = extract_port_info(line)
            vulnerabilities[current_port] = {
                "protocol": "",
                "vulnerabilities": []
            }
    
    return vulnerabilities

def extract_port_info(line):
    match = re.search(r'([0-9]+\/[a-z]+)', line)
    if match:
        return match.group(1)
    return None

def extract_vulnerability_info(line):
    match = re.search(r'([A-Z0-9_\-]+)\s+([0-9\.]+)\s+(https:\/\/vulners\.com\/[^ ]+)\s+\*EXPLOIT\*', line)
    if match:
        return {
            "id": match.group(1),
            "cvss_score": match.group(2),
            "link": match.group(3)
        }
    return None

def save_results(ip_address, vulnerabilities):
    formatted_results = {
        "host": {
            "ip": f"({ip_address})",
            "domain": "",
            "ports": []
        }
    }
    
    for port, data in vulnerabilities.items():
        port_info = {
            f"port:{port}": {
                "protocol": data["protocol"],
                "vulnerabilities": data["vulnerabilities"]
            }
        }
        formatted_results["host"]["ports"].append(port_info)
    
    filename = f"{ip_address}_scan_results.json"
    with open(filename, 'w') as file:
        json.dump(formatted_results, file, indent=4)
    print(f"Scansione completata con successo. Risultati salvati in {filename}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 script.py <ip_address>")
        return
    
    ip_address = sys.argv[1]
    max_attempts = 3
    attempt = 0
    
    while attempt < max_attempts:
        scan_results = scan_ip(ip_address)
        
        if scan_results:
            vulnerabilities = extract_exploit_vulnerabilities(scan_results)
            
            if vulnerabilities:
                save_results(ip_address, vulnerabilities)
                return  # Esci dal loop se la scansione ha avuto successo e ha trovato porte con vulnerabilità
            
        attempt += 1
        print(f"Tentativo {attempt} di scansione fallito.")
    
    print(f"Numero massimo di tentativi raggiunto senza successo per l'IP {ip_address}. Uscita.")

if __name__ == "__main__":
    main()
