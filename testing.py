from scapy.all import ARP, Ether, srp
from network_scanner import scrapScanner


def main():
    
    toPrint = scrapScanner.discover_hosts("192.168.1.0/24")
    print(toPrint)

if __name__ == "__main__":
    main()