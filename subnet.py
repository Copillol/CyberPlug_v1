import concurrent.futures
import subprocess
from ipaddress import ip_network

def ping_ip(ip):
    command = ['ping', '-c', '1', '-W', '1', ip]
    try:
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return ip
    except subprocess.CalledProcessError:
        return None

def bulk_ping(start_ip, end_ip, num_threads=200):
    active_subnets = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_ip = {executor.submit(ping_ip, f"192.168.{i // 256}.{i % 256}"): f"192.168.{i // 256}.{i % 256}" for i in range(start_ip, end_ip)}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            if future.result():
                subnet = ip_network(f"{ip}/24", strict=False)
                active_subnets.add(str(subnet))
    return list(active_subnets)

def main():
    start_ip = 1
    end_ip = 65535  # 192.168.0.1 to 192.168.255.255

    active_subnets = bulk_ping(start_ip, end_ip, num_threads=800)

    if active_subnets:
        for subnet in active_subnets:
            print(subnet)
    else:
        print("\nNo active subnets found.")

if __name__ == "__main__":
    main()
