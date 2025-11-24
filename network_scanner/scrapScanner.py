from scapy.all import *
import socket


    

def discover_hosts(target_ip):


    print(f"[DEBUG] Starting ARP scan on: {target_ip}")

    # Create ARP request packet
    arp_request = ARP(pdst=target_ip)

    # Create Ethernet frame broadcast
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine them
    arp_packet = broadcast / arp_request

    # Send packet and capture response
    answered, unanswered = srp(arp_packet, timeout=2, verbose=False)

    discovered_hosts = []

    for sent, received in answered:
        host_info = {
            "ip": received.psrc,
            "mac": received.hwsrc
        }
        discovered_hosts.append(host_info)

        print(f"[INFO] Host discovered: IP={received.psrc}, MAC={received.hwsrc}")

    if not discovered_hosts:
        print("[DEBUG] No hosts found.")

    return discovered_hosts

def get_active_ports(target_ip):

    allHosts = discover_hosts(target_ip)
    if len(allHosts) == 0:
        return []

    ipv4_addresses = []
    for host in allHosts:
        if isinstance(host, dict) and "ip" in host:
            ipv4_addresses.append(host["ip"])
        elif isinstance(host, tuple):
            ipv4_addresses.append(host[0])
        elif isinstance(host, str):
            ipv4_addresses.append(host)

    print(f"[DEBUG] Starting deep dive on discovered hosts: {ipv4_addresses}")

    common_ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 3389]

    results = []

    for ip in ipv4_addresses:
        for port in common_ports:
            banner = grab_banner(ip, port)
            if banner:
                print(f"[+] {ip}:{port} | {banner.strip()}")
                results.append({"ip": ip, "port": port, "service": banner.strip()})

    return results

def grab_banner(ip, port, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))

        if result == 0:
            # Port is open — attempt to read banner
            try:
                banner = s.recv(1024).decode(errors="ignore")
                if banner.strip():
                    return banner.strip()
            except:
                pass

            # No banner, but port is confirmed open
            return "OPEN (no banner)"

        s.close()
        return None

    except Exception as e:
        return None