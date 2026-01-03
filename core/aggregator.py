import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime
import time
from core.notifier import Notifier

class AttackAggregator:
    def __init__(self, logger):
        self.logger = logger
        self.active_attacks = {}  # Key: (src_ip, attack_type), Value: attack_dict
        self.IDLE_TIMEOUT = 60  # 60 seconds of inactivity to "finish" an attack
        self.notifier = Notifier()

    def add_alert(self, alert_data):
        src_ip = alert_data.get("src_ip")
        attack_type = alert_data.get("type")
        timestamp = alert_data.get("timestamp")
        description = alert_data.get("description")

        key = (src_ip, attack_type)
        now = time.time()

        if key in self.active_attacks:
            attack = self.active_attacks[key]
            attack["count"] += 1
            attack["last_seen"] = now
            attack["end_time"] = timestamp
            # We keep a list of unique descriptions or just the latest? 
            # User wants "comprehensive details". 
            if description not in attack["details"]:
                attack["details"].append(description)
        else:
            self.active_attacks[key] = {
                "src_ip": src_ip,
                "type": attack_type,
                "start_time": timestamp,
                "end_time": timestamp,
                "first_seen": now,
                "last_seen": now,
                "count": 1,
                "details": [description]
            }
            # New Attack! Notify via WhatsApp
            self.notifier.send_notification(attack_type, src_ip, timestamp)
        
        # Every time we add an alert, we also update the live view with a safe snapshot
        # We copy the dicts to avoid "dictionary changed size during iteration" in logger
        snapshot = [dict(a) for a in self.active_attacks.values()]
        for attack_copy in snapshot:
            attack_copy["details"] = list(attack_copy["details"])
        self.logger.write_active_attacks(snapshot)
        
        self.cleanup()

    def cleanup(self):
        now = time.time()
        to_remove = []
        # Safe iteration by using list of keys
        for key in list(self.active_attacks.keys()):
            attack = self.active_attacks[key]
            if now - attack["last_seen"] > self.IDLE_TIMEOUT:
                # Attack is considered finished
                self.logger.log_attack(attack)
                to_remove.append(key)
        
        for key in to_remove:
            del self.active_attacks[key]
        
        # If we removed any, update the live view with a safe snapshot
        if to_remove:
            snapshot = [dict(a) for a in self.active_attacks.values()]
            for attack_copy in snapshot:
                attack_copy["details"] = list(attack_copy["details"])
            self.logger.write_active_attacks(snapshot)

    def get_active_attacks(self):
        # Return a list of active attacks for immediate UI display if needed
        return list(self.active_attacks.values())
