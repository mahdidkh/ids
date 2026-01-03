import requests
import json
import os
import urllib.parse

class Notifier:
    def __init__(self, config_file="logs/notifications.json"):
        self.config_file = config_file
        self.wa_phone = ""
        self.wa_api_key = ""
        self.tg_bot_token = ""
        self.tg_chat_id = ""
        self.enabled_platform = "none" # "whatsapp", "telegram", or "both"
        self._load_config()

    def _load_config(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r") as f:
                    config = json.load(f)
                    self.wa_phone = config.get("wa_phone", "")
                    self.wa_api_key = config.get("wa_api_key", "")
                    self.tg_bot_token = config.get("tg_bot_token", "")
                    self.tg_chat_id = config.get("tg_chat_id", "")
                    self.enabled_platform = config.get("enabled_platform", "none")
            except:
                pass

    def send_notification(self, attack_type, src_ip, timestamp):
        if self.enabled_platform == "none":
            return False

        message = (
            f"🚨 *IDS ALERT*\n"
            f"*Type*: {attack_type}\n"
            f"*Source*: {src_ip}\n"
            f"*Time*: {timestamp}\n"
            f"Check dashboard for details!"
        )
        
        success = False
        
        # WhatsApp (CallMeBot backup)
        if self.enabled_platform in ["whatsapp", "both"] and self.wa_phone and self.wa_api_key:
            encoded_msg = urllib.parse.quote(message)
            url = f"https://api.callmebot.com/whatsapp.php?phone={self.wa_phone}&text={encoded_msg}&apikey={self.wa_api_key}"
            try:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200: success = True
            except: pass

        # DIRECT Telegram Bot API
        if self.enabled_platform in ["telegram", "both"] and self.tg_bot_token and self.tg_chat_id:
            url = f"https://api.telegram.org/bot{self.tg_bot_token}/sendMessage"
            payload = {
                "chat_id": self.tg_chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }
            try:
                resp = requests.post(url, json=payload, timeout=10)
                if resp.status_code == 200: 
                    success = True
                else: 
                    print(f"[!] Telegram API Error: {resp.text}")
            except Exception as e: 
                print(f"[!] Telegram request failed: {e}")
            
        return success
