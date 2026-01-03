import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import sniff, IP, TCP, UDP, ARP, DNS, DNSQR, DNSRR, Ether, conf
from core.detection import DetectionEngine
import traceback

engine = DetectionEngine()
conf.resolve_ips = False # Teacher says: Always use raw IPs for a security system!

def packet_callback(packet):
    try:
        # Extract source MAC if possible (Ethernet layer)
        src_mac = packet[Ether].src if Ether in packet else None

        # 1. --- ARP Analysis ---
        if ARP in packet:
            src_ip = packet[ARP].psrc
            op = packet[ARP].op # 1=req, 2=reply
            alert = engine.detect_arp_spoofing(src_ip, src_mac, op)
            if alert: print(alert)

        # 2. --- IP Analysis ---
        if IP in packet:
            src_ip = packet[IP].src
            
            # Check for IP Spoofing (MAC Mismatch)
            if src_mac:
                alert = engine.detect_ip_spoofing(src_ip, src_mac)
                if alert: print(alert)

            # --- TCP Analysis ---
            if TCP in packet:
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                
                # Check for SYN Flood
                alert = engine.detect_syn_flood(src_ip, flags, dst_port)
                if alert: print(alert)
                    
                # Check for Port Scan
                alert = engine.detect_port_scan(src_ip, dst_port)
                if alert: print(alert)

                # Check for Brute Force (SSH, FTP, etc.)
                if flags == "S":
                    alert = engine.detect_brute_force(src_ip, dst_port)
                    if alert: print(alert)

                # Check for Abnormal Flags (NULL, XMAS, etc.)
                alert = engine.detect_abnormal_flags(src_ip, flags, dst_port)
                if alert: print(alert)

            # --- DNS Analysis (UDP port 53) ---
            if UDP in packet and DNS in packet:
                dns_layer = packet[DNS]
                if dns_layer.qr == 1: # It's a Response
                    dns_id = dns_layer.id
                    # Get the query name
                    qname = dns_layer[DNSQR].qname.decode() if DNSQR in dns_layer else "unknown"
                    # Get all Answer IPs
                    answers = []
                    if dns_layer.ancount > 0:
                        for i in range(dns_layer.ancount):
                            res = packet.getlayer(DNSRR, nb=i+1)
                            if res and res.type == 1: # A record (IPv4)
                                answers.append(res.rdata)
                    
                    if answers:
                        alert = engine.detect_dns_spoofing(dns_id, qname, answers)
                        if alert: print(alert)

    except Exception:
        traceback.print_exc()

def start_sniffing():
    print(f"[*] IDS active on: {conf.iface}")
    print("[*] Monitoring for attacks... (Ctrl+C to stop)")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffing()
