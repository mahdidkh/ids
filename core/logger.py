import json
import datetime
import os

class LogManager:
    def __init__(self, log_file=None):
        # Calculate project root (1 level up from core/logger.py)
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.log_dir = os.path.join(self.base_dir, "logs")
        
        if log_file:
            # If a custom log file is provided, use it either as absolute or relative to base
            if os.path.isabs(log_file):
                self.log_file = log_file
            else:
                self.log_file = os.path.join(self.base_dir, log_file)
        else:
            self.log_file = os.path.join(self.log_dir, "alerts.json")

        self.last_alerts = {}  # Cache to aggregate frequent alerts: {(ip, type): {data, last_time}}
        self.aggregation_window = 5  # Seconds to aggregate similar alerts
        
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

    def log_alert(self, src_ip, attack_type, description):
        """
        Logs an alert with aggregation logic to prevent redundant entries.
        """
        now = datetime.datetime.now()
        key = (src_ip, attack_type)
        
        # Check if we should aggregate
        if key in self.last_alerts:
            last_entry = self.last_alerts[key]
            if (now - last_entry["time"]).total_seconds() < self.aggregation_window:
                last_entry["count"] += 1
                last_entry["time"] = now
                # We don't write to disk yet; we'll either write on window expiry or periodic flush
                # For now, let's just log every 10th aggregate or if it's new
                if last_entry["count"] % 10 != 0:
                    return

        # If not aggregated or time to flush
        count = 1
        if key in self.last_alerts:
            count = self.last_alerts[key]["count"]
            # Reset count after flush
            self.last_alerts[key]["count"] = 1
            self.last_alerts[key]["time"] = now
        else:
            self.last_alerts[key] = {"count": 1, "time": now}

        full_description = description
        if count > 1:
            full_description = f"[Aggregated {count} times] {description}"

        alert_data = {
            "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip if src_ip != "DNS_Server" else self._guess_dns_ip(),
            "type": attack_type,
            "description": full_description,
            "count": count
        }
        self._write_to_json(self.log_file, alert_data)

    def _guess_dns_ip(self):
        # Fallback if IP is missing but we know it's a DNS event
        return "192.168.1.1" # Common gateway/dns

    def log_attack(self, attack_data):
        attack_data["logged_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Ensure we don't have "DNS_Server" as IP
        if attack_data.get("src_ip") == "DNS_Server":
            attack_data["src_ip"] = self._guess_dns_ip()
            
        attack_file = os.path.join(self.log_dir, "attacks.json")
        self._write_to_json(attack_file, attack_data)

    def write_active_attacks(self, active_attacks_list):
        try:
            # Clean up active attacks data
            for attack in active_attacks_list:
                if attack.get("src_ip") == "DNS_Server":
                    attack["src_ip"] = self._guess_dns_ip()

            active_file = os.path.join(self.log_dir, "active_attacks.json")
            with open(active_file, "w", encoding="utf-8") as f:
                json.dump(active_attacks_list, f, indent=4)
        except Exception as e:
            print(f"[!] Error writing active attacks: {e}")

    def _write_to_json(self, file_path, new_entry):
        try:
            logs = []
            if os.path.exists(file_path):
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (json.JSONDecodeError, ValueError):
                    logs = []
            
            if not isinstance(logs, list):
                logs = []

            logs.append(new_entry)
            
            # Rotation: Keep last 500 items to keep UI snappy
            if len(logs) > 500:
                logs = logs[-500:]
            
            # ATOMIC WRITE
            temp_file = file_path + ".tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4)
            
            os.replace(temp_file, file_path)
            
        except Exception as e:
            print(f"[!] Error writing log: {e}")
