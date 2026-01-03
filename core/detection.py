import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.logger import LogManager
from core.aggregator import AttackAggregator
import time

class DetectionEngine:
    def __init__(self):
        # Teachers says: We initialize the reporter who will write the history
        self.logger = LogManager()
        self.aggregator = AttackAggregator(self.logger)
        self.whitelist_file = "logs/whitelist.json"
        
        # We now store: { "ip": [timestamp1, timestamp2, ...] }
        self.syn_times = {}
        # We store: { "ip": { "port": timestamp, ... } }
        self.port_scan_times = {}
        # We also track which ports are hit by SYNs specifically
        self.syn_ports = {}
        
        self.BRUTE_FORCE_THRESHOLD = 5 # 5 attempts in 30s
        self.BRUTE_FORCE_WINDOW = 30
        
        # Whitelist Tracking
        self.whitelist = []
        self.last_whitelist_load = 0
        self._load_whitelist()
        
        # --- Spoofing & Brute Force Tracking ---
        self.arp_cache = {} # { "ip": "mac" }
        self.dns_queries = {} # { "tx_id": { "name": "...", "responses": [] } }
        self.brute_force_attempts = {} # { (ip, port): [timestamps] }

        # Settings: How many packets in how much time?
        self.WINDOW_SIZE = 10     # Look at the last 10 seconds
        self.FLOOD_THRESHOLD = 30 # 30 SYNs in 10 seconds is suspicious
        self.SCAN_THRESHOLD = 15  # Back to realistic value

    def is_whitelisted(self, ip):
        # Reload if file changed or every 5 seconds
        if time.time() - self.last_whitelist_load > 5:
            self._load_whitelist()
        return ip in self.whitelist

    def _load_whitelist(self):
        import json
        import os
        if os.path.exists(self.whitelist_file):
            try:
                mtime = os.path.getmtime(self.whitelist_file)
                if mtime > self.last_whitelist_load:
                    with open(self.whitelist_file, "r") as f:
                        self.whitelist = json.load(f)
                        self.last_whitelist_load = mtime
            except:
                pass
        else:
            self.whitelist = ["127.0.0.1", "::1"]
            self.last_whitelist_load = time.time()

    def _save_whitelist(self):
        import json
        try:
            with open(self.whitelist_file, "w") as f:
                json.dump(self.whitelist, f, indent=4)
        except Exception as e:
            print(f"[!] Error saving whitelist: {e}")

    def add_to_whitelist(self, ip):
        if ip not in self.whitelist:
            self.whitelist.append(ip)
            self._save_whitelist()
            return True
        return False

    def remove_from_whitelist(self, ip):
        if ip in self.whitelist and ip not in ["127.0.0.1", "::1"]:
            self.whitelist.remove(ip)
            self._save_whitelist()
            return True
        return False

    def detect_syn_flood(self, src_ip, tcp_flags, dst_port):
        if self.is_whitelisted(src_ip): return None
        
        if tcp_flags == "S":
            now = time.time()
            if src_ip not in self.syn_times:
                self.syn_times[src_ip] = []
            if src_ip not in self.syn_ports:
                self.syn_ports[src_ip] = set()
            
            self.syn_times[src_ip].append(now)
            self.syn_ports[src_ip].add(dst_port)
            
            # Keep only last WINDOW_SIZE seconds
            self.syn_times[src_ip] = [t for t in list(self.syn_times[src_ip]) if now - t < self.WINDOW_SIZE]
            
            packet_count = len(self.syn_times[src_ip])
            port_count = len(self.syn_ports[src_ip])
            
            # Teacher says: Here is the "Brain" of the IDS!
            # A true flood has much more packets than ports (high density).
            if packet_count > self.FLOOD_THRESHOLD:
                # 1. Targeted Flood: High volume on very few ports
                if port_count <= 5:
                    ports_list = sorted(list(self.syn_ports[src_ip]))
                    msg = f"Targeted SYN Flood on ports {ports_list}: {packet_count} pks from {src_ip}"
                    
                    alert_data = {"src_ip": src_ip, "type": "SYN Flood (Targeted)", "description": msg, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
                    self.logger.log_alert(src_ip, alert_data["type"], msg)
                    self.aggregator.add_alert(alert_data)
                    
                    self.syn_times[src_ip] = [] 
                    self.syn_ports[src_ip] = set()
                    return f"[!!!] ALERT: {msg}"
                
                # 2. Global Flood: MASSIVE volume across many ports
                # We only call it "Flood" if there are at least 5 packets per port on average
                elif packet_count > port_count * 5:
                    msg = f"Global SYN Flood: MASSIVE volume ({packet_count} pks over {port_count} ports) from {src_ip}"
                    
                    alert_data = {"src_ip": src_ip, "type": "SYN Flood (Global)", "description": msg, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
                    self.logger.log_alert(src_ip, alert_data["type"], msg)
                    self.aggregator.add_alert(alert_data)
                    
                    self.syn_times[src_ip] = [] 
                    self.syn_ports[src_ip] = set()
                    return f"[!!!] ALERT: {msg}"
                
                # 3. Otherwise: It's probably just a Port Scan.
                # We return None because 'detect_port_scan' will handle it.
        return None

    def detect_port_scan(self, src_ip, dst_port):
        if self.is_whitelisted(src_ip): return None
        
        # Teacher says: We only watch "Service Ports" (1-1024) to avoid browser noise
        if dst_port > 1024:
            return None
        
        now = time.time()
        if src_ip not in self.port_scan_times:
            self.port_scan_times[src_ip] = {}
            
        # Store port and time
        self.port_scan_times[src_ip][dst_port] = now
        
        # Remove ports older than WINDOW_SIZE
        # Safe iteration to avoid 'dictionary changed size' error
        self.port_scan_times[src_ip] = {p: t for p, t in list(self.port_scan_times[src_ip].items()) if now - t < self.WINDOW_SIZE}
        
        if len(self.port_scan_times[src_ip]) > self.SCAN_THRESHOLD:
            msg = f"SENSITIVE Port scan: {len(self.port_scan_times[src_ip])} low-ports in {self.WINDOW_SIZE}s from {src_ip}"
            
            alert_data = {"src_ip": src_ip, "type": "Port Scan", "description": msg, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
            self.logger.log_alert(src_ip, alert_data["type"], msg)
            self.aggregator.add_alert(alert_data)
            
            self.port_scan_times[src_ip] = {}
            return f"[!!!] ALERT: {msg}"
        return None

    # --- NEW: Spoofing Detection Methods ---

    def detect_arp_spoofing(self, src_ip, src_mac, op):
        # op=1 is request, op=2 is reply
        if self.is_whitelisted(src_ip): return None
        
        if op == 2: # ARP Reply
            if src_ip in self.arp_cache:
                old_mac = self.arp_cache[src_ip]
                if old_mac.lower() != src_mac.lower():
                    msg = f"ARP Spoofing Detected! IP {src_ip} moved from {old_mac} to {src_mac}"
                    alert_data = {"src_ip": src_ip, "type": "ARP Spoofing", "description": msg, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
                    self.logger.log_alert(src_ip, alert_data["type"], msg)
                    self.aggregator.add_alert(alert_data)
                    return f"[!!!] ALERT: {msg}"
            
            # Update cache with latest known MAC
            self.arp_cache[src_ip] = src_mac
        return None

    def detect_ip_spoofing(self, src_ip, src_mac):
        if self.is_whitelisted(src_ip): return None
        
        # If we know this IP belongs to a different MAC in our ARP cache
        if src_ip in self.arp_cache:
            known_mac = self.arp_cache[src_ip]
            if known_mac.lower() != src_mac.lower():
                msg = f"IP Spoofing? Packet from {src_ip} has MAC {src_mac}, but expected {known_mac}"
                alert_data = {"src_ip": src_ip, "type": "IP Spoofing", "description": msg, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
                self.logger.log_alert(src_ip, alert_data["type"], msg)
                self.aggregator.add_alert(alert_data)
                return f"[!!!] ALERT: {msg}"
        return None

    def detect_dns_spoofing(self, dns_id, dns_name, answers):
        # Logic: If we see multiple responses for same ID with different IPs!
        if dns_id not in self.dns_queries:
            self.dns_queries[dns_id] = {"name": dns_name, "ips": set()}
        
        current_query = self.dns_queries[dns_id]
        
        # DNS responses can have multiple IPs, we add them to a set
        new_ips = set(answers)
        if current_query["ips"] and not new_ips.issubset(current_query["ips"]):
            msg = f"DNS Spoofing Detected! Conflict for {dns_name} (ID: {dns_id}): {list(current_query['ips'])} vs {list(new_ips)}"
            alert_data = {"src_ip": "DNS_Server", "type": "DNS Spoofing", "description": msg, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
            self.logger.log_alert("DNS_Server", alert_data["type"], msg)
            self.aggregator.add_alert(alert_data)
            return f"[!!!] ALERT: {msg}"
        
        current_query["ips"].update(new_ips)
        return None

    def detect_brute_force(self, src_ip, dst_port):
        sensitive_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            445: "SMB",
            3389: "RDP",
            3306: "MySQL"
        }
        
        if dst_port not in sensitive_ports:
            return None
            
        service_name = sensitive_ports[dst_port]
        key = (src_ip, dst_port)
        now = time.time()
        
        if key not in self.brute_force_attempts:
            self.brute_force_attempts[key] = []
            
        self.brute_force_attempts[key].append(now)
        
        # Cleanup old attempts
        self.brute_force_attempts[key] = [t for t in self.brute_force_attempts[key] if now - t < self.BRUTE_FORCE_WINDOW]
        
        if len(self.brute_force_attempts[key]) > self.BRUTE_FORCE_THRESHOLD:
            msg = f"Brute Force Attempt detected on {service_name} (Port {dst_port}) from {src_ip}: {len(self.brute_force_attempts[key])} attempts in {self.BRUTE_FORCE_WINDOW}s"
            alert_data = {"src_ip": src_ip, "type": f"Brute Force ({service_name})", "description": msg, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
            self.logger.log_alert(src_ip, alert_data["type"], msg)
            self.aggregator.add_alert(alert_data)
            
            # Reset to avoid spamming alerts for every packet after threshold
            self.brute_force_attempts[key] = []
            return f"[!!!] ALERT: {msg}"
            
        return None

    def detect_abnormal_flags(self, src_ip, tcp_flags, dst_port):
        if self.is_whitelisted(src_ip): return None
        
        # 1. NULL Scan: No flags set
        if tcp_flags == "" or tcp_flags == 0:
            msg = f"NULL Scan detected from {src_ip} to port {dst_port}"
            alert_data = {"src_ip": src_ip, "type": "Abnormal Flags (NULL Scan)", "description": msg, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
            self.logger.log_alert(src_ip, alert_data["type"], msg)
            self.aggregator.add_alert(alert_data)
            return f"[!!!] ALERT: {msg}"
            
        # 2. XMAS Scan: FIN, PSH, and URG set
        # Scapy represents flags as a string like "FPU"
        if "F" in tcp_flags and "P" in tcp_flags and "U" in tcp_flags:
            msg = f"XMAS Scan detected from {src_ip} to port {dst_port}"
            alert_data = {"src_ip": src_ip, "type": "Abnormal Flags (XMAS Scan)", "description": msg, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
            self.logger.log_alert(src_ip, alert_data["type"], msg)
            self.aggregator.add_alert(alert_data)
            return f"[!!!] ALERT: {msg}"
            
        # 3. Illegal Combination: SYN + FIN
        if "S" in tcp_flags and "F" in tcp_flags:
            msg = f"Illegal Flag Combo (SYN+FIN) detected from {src_ip} to port {dst_port}"
            alert_data = {"src_ip": src_ip, "type": "Abnormal Flags (SYN+FIN)", "description": msg, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
            self.logger.log_alert(src_ip, alert_data["type"], msg)
            self.aggregator.add_alert(alert_data)
            return f"[!!!] ALERT: {msg}"
            
        return None
