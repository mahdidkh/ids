import sys
import os
import time
import json

# Teacher says: On s'assure que Python trouve bien le dossier "core"
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.logger import LogManager

class DetectionEngine:
    def __init__(self):
        # Initialisation du "cerveau" de l'IDS
        self.logger = LogManager()
        
        # Fichiers de configuration
        self.whitelist_file = "logs/whitelist.json"
        self.firewall_file = "logs/firewall_rules.json"
        
        # Mémoire pour les détections
        self.syn_times = {}           # Pour le SYN Flood
        self.port_scan_times = {}     # Pour le Scan de Ports
        self.brute_force_attempts = {} # Pour le Brute Force
        self.arp_cache = {}           # Pour le Spoofing ARP
        self.dns_queries = {}         # Pour le Spoofing DNS
        
        # Listes de sécurité
        self.whitelist = []
        self.blocklist = []
        self.last_reload = 0
        
        # Seuils de détection (faciles à modifier)
        self.SYNC_LIMIT = 30   # 30 paquets SYN
        self.SCAN_LIMIT = 15   # 15 ports différents
        self.BRUTE_LIMIT = 5   # 5 essais de connexion
        self.WINDOW = 10       # Fenêtre de temps de 10 secondes

    def is_safe(self, ip):
        """Vérifie si une IP est autorisée ou déjà bloquée."""
        now = time.time()
        # On recharge les listes toutes les 5 secondes
        if now - self.last_reload > 5:
            self._load_lists()
            self.last_reload = now
        
        if ip in self.whitelist: return True
        if ip in self.blocklist: return True  # On ignore les IPs déjà bloquées
        return False

    def _load_lists(self):
        """Charge la Whitelist et la Blocklist depuis les fichiers JSON."""
        # Whitelist
        if os.path.exists(self.whitelist_file):
            try:
                with open(self.whitelist_file, "r") as f: self.whitelist = json.load(f)
            except: self.whitelist = ["127.0.0.1"]
        
        # Blocklist (Firewall)
        if os.path.exists(self.firewall_file):
            try:
                with open(self.firewall_file, "r") as f:
                    self.blocklist = json.load(f).get("blocklist", [])
            except: self.blocklist = []

    # --- 1. DETECTION SYN FLOOD ---
    def detect_syn_flood(self, src_ip, tcp_flags, dst_port):
        if self.is_safe(src_ip) or tcp_flags != "S": return None
        
        now = time.time()
        if src_ip not in self.syn_times: self.syn_times[src_ip] = []
        
        # On ajoute le nouveau paquet et on nettoie les vieux
        self.syn_times[src_ip].append(now)
        self.syn_times[src_ip] = [t for t in self.syn_times[src_ip] if now - t < self.WINDOW]
        
        if len(self.syn_times[src_ip]) > self.SYNC_LIMIT:
            msg = f"SYN Flood detecté : {len(self.syn_times[src_ip])} paquets en {self.WINDOW}s"
            self.logger.log_alert(src_ip, "SYN Flood", msg)
            self.syn_times[src_ip] = [] # Reset
            return f"[!!!] ALERT: {msg}"
        return None

    # --- 2. DETECTION PORT SCAN ---
    def detect_port_scan(self, src_ip, dst_port):
        if self.is_safe(src_ip) or dst_port > 1024: return None
        
        now = time.time()
        if src_ip not in self.port_scan_times: self.port_scan_times[src_ip] = {}
        
        # On enregistre le port visité
        self.port_scan_times[src_ip][dst_port] = now
        self.port_scan_times[src_ip] = {p: t for p, t in self.port_scan_times[src_ip].items() if now - t < self.WINDOW}
        
        if len(self.port_scan_times[src_ip]) > self.SCAN_LIMIT:
            msg = f"Scan de Ports detecté : {len(self.port_scan_times[src_ip])} ports scannés"
            self.logger.log_alert(src_ip, "Port Scan", msg)
            self.port_scan_times[src_ip] = {}
            return f"[!!!] ALERT: {msg}"
        return None

    # --- 3. DETECTION BRUTE FORCE ---
    def detect_brute_force(self, src_ip, dst_port):
        if self.is_safe(src_ip): return None
        
        services = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP"}
        if dst_port not in services: return None
        
        now = time.time()
        key = (src_ip, dst_port)
        if key not in self.brute_force_attempts: self.brute_force_attempts[key] = []
        
        self.brute_force_attempts[key].append(now)
        self.brute_force_attempts[key] = [t for t in self.brute_force_attempts[key] if now - t < 30]
        
        if len(self.brute_force_attempts[key]) > self.BRUTE_LIMIT:
            msg = f"Brute Force sur {services[dst_port]} ({len(self.brute_force_attempts[key])} essais)"
            self.logger.log_alert(src_ip, f"Brute Force ({services[dst_port]})", msg)
            self.brute_force_attempts[key] = []
            return f"[!!!] ALERT: {msg}"
        return None

    # --- 4. DETECTION SPOOFING (ARP/IP/DNS) ---
    def detect_arp_spoofing(self, src_ip, src_mac, op):
        if self.is_safe(src_ip) or op != 2: return None # On surveille les "Replies"
        
        if src_ip in self.arp_cache and self.arp_cache[src_ip].lower() != src_mac.lower():
            msg = f"ARP Spoofing! {src_ip} a changé d'adresse MAC ({self.arp_cache[src_ip]} -> {src_mac})"
            self.logger.log_alert(src_ip, "ARP Spoofing", msg)
            return f"[!!!] ALERT: {msg}"
        
        self.arp_cache[src_ip] = src_mac
        return None

    def detect_ip_spoofing(self, src_ip, src_mac):
        if self.is_safe(src_ip): return None
        # On vérifie si la MAC envoyant cet IP est celle qu'on connaît
        if src_ip in self.arp_cache and self.arp_cache[src_ip].lower() != src_mac.lower():
            msg = f"IP Spoofing! L'IP {src_ip} est utilisée par une MAC inconnue : {src_mac}"
            self.logger.log_alert(src_ip, "IP Spoofing", msg)
            return f"[!!!] ALERT: {msg}"
        return None

    def detect_dns_spoofing(self, dns_id, dns_name, answers):
        if dns_id not in self.dns_queries:
            self.dns_queries[dns_id] = {"name": dns_name, "ips": set(answers)}
            return None
        
        # Si on voit une deuxième réponse différente pour le même ID
        if not set(answers).issubset(self.dns_queries[dns_id]["ips"]):
            msg = f"DNS Spoofing sur {dns_name}! Réponses contradictoires détectées."
            self.logger.log_alert("Serv_DNS", "DNS Spoofing", msg)
            return f"[!!!] ALERT: {msg}"
        return None

    # --- 5. DETECTION DRAPEAUX ANORMAUX (NULL/XMAS) ---
    def detect_abnormal_flags(self, src_ip, tcp_flags, dst_port):
        if self.is_safe(src_ip): return None
        
        msg = ""
        if not tcp_flags: msg = "NULL Scan (aucun drapeau TCP)"
        elif "F" in tcp_flags and "P" in tcp_flags and "U" in tcp_flags: msg = "XMAS Scan (F+P+U)"
        elif "S" in tcp_flags and "F" in tcp_flags: msg = "SYN+FIN (Combinaison illégale)"
        
        if msg:
            self.logger.log_alert(src_ip, "Drapeaux Anormaux", msg)
            return f"[!!!] ALERT: {msg}"
        return None
