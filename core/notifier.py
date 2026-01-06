import requests
import json
import os

class Notifier:
    def __init__(self, config_file="logs/notifications.json"):
        self.config_file = config_file
        self.tg_bot_token = ""
        self.tg_chat_id = ""
        self.is_enabled = False
        self._load_config()

    def _load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r") as f:
                    config = json.load(f)
                    self.tg_bot_token = config.get("tg_bot_token", "")
                    self.tg_chat_id = config.get("tg_chat_id", "")
                    # Simple check for Telegram only
                    self.is_enabled = config.get("enabled_platform") in ["telegram", "both"]
            except:
                pass

    def send_notification(self, attack_type, src_ip, timestamp):
        if not self.is_enabled or not self.tg_bot_token or not self.tg_chat_id:
            return False

        message = (
            f"🚨 *IDS ALERT*\n"
            f"*Type*: {attack_type}\n"
            f"*Source*: {src_ip}\n"
            f"*Time*: {timestamp}\n"
            f"Check dashboard for details!"
        )
        
        # Telegram API call
        url = f"https://api.telegram.org/bot{self.tg_bot_token}/sendMessage"
        payload = {
            "chat_id": self.tg_chat_id,
            "text": message,
            "parse_mode": "Markdown"
        }
        
        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 200: 
                return True
            else: 
                print(f"[!] Telegram API Error: {resp.text}")
        except Exception as e: 
            print(f"[!] Telegram request failed: {e}")
            
        return False
