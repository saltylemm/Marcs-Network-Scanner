from scapy.all import ARP, Ether, srp

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