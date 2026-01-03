from scapy.all import Ether, ARP, IP, UDP, DNS, DNSQR, DNSRR, TCP
import time
import os

def simulate_arp_spoof():
    print("[*] Simulating ARP Spoofing...")
    # 1. Establish a "known" MAC for 192.168.1.50
    p1 = Ether(src="aa:bb:cc:dd:ee:ff")/ARP(op=2, psrc="192.168.1.50", hwsrc="aa:bb:cc:dd:ee:ff")
    # 2. Send it to the interface
    from scapy.all import sendp
    sendp(p1, verbose=False)
    time.sleep(1)
    
    # 3. Send a "spoofed" ARP reply with same IP but different MAC
    p2 = Ether(src="11:22:33:44:55:66")/ARP(op=2, psrc="192.168.1.50", hwsrc="11:22:33:44:55:66")
    sendp(p2, verbose=False)
    print("[+] ARP Spoofing Sim complete.")

def simulate_ip_spoof():
    print("[*] Simulating IP Spoofing (MAC Mismatch)...")
    # We already "labeled" 192.168.1.50 as 11:22:33... in ARP cache
    # Now send a TCP packet from 192.168.1.50 but with a DIFFERENT MAC
    p = Ether(src="ff:ff:ff:ff:ff:ff")/IP(src="192.168.1.50", dst="1.2.3.4")/TCP(dport=80)
    from scapy.all import sendp
    sendp(p, verbose=False)
    print("[+] IP Spoofing Sim complete.")

def simulate_dns_spoof():
    print("[*] Simulating DNS Spoofing...")
    tx_id = 1234
    domain = "google.com."
    
    # Response 1
    p1 = IP(src="8.8.8.8", dst="192.168.1.10")/UDP(sport=53, dport=12345)/DNS(id=tx_id, qr=1, qd=DNSQR(qname=domain), an=DNSRR(rrname=domain, rdata="8.8.8.8"))
    
    # Response 2 (Spoofed - different IP for same domain and ID)
    p2 = IP(src="8.8.8.8", dst="192.168.1.10")/UDP(sport=53, dport=12345)/DNS(id=tx_id, qr=1, qd=DNSQR(qname=domain), an=DNSRR(rrname=domain, rdata="6.6.6.6"))
    
    from scapy.all import send
    send(p1, verbose=False)
    time.sleep(0.5)
    send(p2, verbose=False)
    print("[+] DNS Spoofing Sim complete.")

if __name__ == "__main__":
    print("=== IDS Spoofing Verification ===")
    simulate_arp_spoof()
    time.sleep(1)
    simulate_ip_spoof()
    time.sleep(1)
    simulate_dns_spoof()
    print("\nCheck your dashboard or logs/alerts.json for results!")
