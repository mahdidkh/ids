import json
import os

# Calculate project root (3 levels up from this file: ui/utils/data_handler.py)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(BASE_DIR, "logs")

ALERTS_FILE = os.path.join(LOG_DIR, "attacks.json")
ATTACKS_FILE = os.path.join(LOG_DIR, "attacks.json")
FIREWALL_FILE = os.path.join(LOG_DIR, "firewall_rules.json")

def read_json_file(filepath):
    """Reads a JSON file and returns data, or empty list if failed."""
    if not os.path.exists(filepath):
        return []
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            return [] # Expected list of records
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return []

def get_alerts():
    return read_json_file(ALERTS_FILE)

def get_attacks():
    return read_json_file(ATTACKS_FILE)

def get_firewall_rules():
    if not os.path.exists(FIREWALL_FILE):
        return {"blocklist": [], "whitelist": []}
    
    try:
        with open(FIREWALL_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {"blocklist": [], "whitelist": []}

def save_firewall_rules(rules):
    try:
        with open(FIREWALL_FILE, "w", encoding="utf-8") as f:
            json.dump(rules, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving firewall rules: {e}")
        return False
