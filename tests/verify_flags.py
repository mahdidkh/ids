from scapy.all import IP, TCP, send
import time

def simulate_null_scan():
    print("[*] Simulating NULL Scan (No flags)...")
    p = IP(src="1.1.1.1", dst="192.168.1.1")/TCP(dport=80, flags="")
    send(p, verbose=False)
    print("[+] NULL Scan packet sent.")

def simulate_xmas_scan():
    print("[*] Simulating XMAS Scan (FPU flags)...")
    p = IP(src="2.2.2.2", dst="192.168.1.1")/TCP(dport=80, flags="FPU")
    send(p, verbose=False)
    print("[+] XMAS Scan packet sent.")

def simulate_syn_fin_scan():
    print("[*] Simulating SYN+FIN Illegal Combination...")
    p = IP(src="3.3.3.3", dst="192.168.1.1")/TCP(dport=80, flags="SF")
    send(p, verbose=False)
    print("[+] SYN+FIN packet sent.")

if __name__ == "__main__":
    print("=== IDS Abnormal Flags Verification ===")
    simulate_null_scan()
    time.sleep(1)
    simulate_xmas_scan()
    time.sleep(1)
    simulate_syn_fin_scan()
    print("\nCheck your dashboard or logs/alerts.json for results!")
