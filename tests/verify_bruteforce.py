from scapy.all import IP, TCP, send
import time

def simulate_ssh_brute_force():
    print("[*] Simulating SSH Brute Force (Port 22)...")
    attacker_ip = "10.10.10.10"
    for i in range(7):
        # Send a SYN packet to port 22
        p = IP(src=attacker_ip, dst="192.168.1.1")/TCP(dport=22, flags="S")
        send(p, verbose=False)
        print(f"  [+] Attempt {i+1}/7 sent")
        time.sleep(0.5)
    print("[+] SSH Brute Force Sim complete.")

def simulate_ftp_brute_force():
    print("[*] Simulating FTP Brute Force (Port 21)...")
    attacker_ip = "11.11.11.11"
    for i in range(7):
        p = IP(src=attacker_ip, dst="192.168.1.1")/TCP(dport=21, flags="S")
        send(p, verbose=False)
        print(f"  [+] Attempt {i+1}/7 sent")
        time.sleep(0.5)
    print("[+] FTP Brute Force Sim complete.")

if __name__ == "__main__":
    print("=== IDS Brute Force Verification ===")
    simulate_ssh_brute_force()
    time.sleep(2)
    simulate_ftp_brute_force()
    print("\nCheck your dashboard or logs/alerts.json for results!")
