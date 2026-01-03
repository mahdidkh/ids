import sys
import os
import time

# Add parent directory to path to import core
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.logger import LogManager

def run_stress_test():
    print("[*] Starting Logger Stress Test...")
    logger = LogManager("logs/test_alerts.json")
    
    # Clean up previous test file
    if os.path.exists("logs/test_alerts.json"):
        os.remove("logs/test_alerts.json")
    
    start_time = time.time()
    
    # 1. Test Aggregation: Send 100 identical alerts in quick succession
    print("[*] Testing Aggregation (100 similar alerts)...")
    for _ in range(100):
        logger.log_alert("1.1.1.1", "Test Attack", "This should be aggregated")
    
    # Verify aggregation immediately before rotation
    import json
    with open("logs/test_alerts.json", "r") as f:
        logs_pre = json.load(f)
    
    agg_entry = next((l for l in logs_pre if l["src_ip"] == "1.1.1.1"), None)
    if agg_entry and agg_entry.get("count", 0) > 1:
        print(f"[V] Aggregation verified early (count {agg_entry['count']})")
    else:
        print("[X] Aggregation failed early!")

    # 2. Test Different IPs: Send 10 different alerts
    print("[*] Testing Different IPs (10 unique alerts)...")
    for i in range(10):
        logger.log_alert(f"192.168.1.{i}", "Unique Attack", f"Alert number {i}")
    
    # 3. Test Rotation: Send 600 unique alerts (rotation limit is 500)
    print("[*] Testing Rotation (600 unique alerts)...")
    for i in range(600):
        logger.log_alert(f"10.0.0.{i}", "Rotation Test", f"Log {i}")
        if i % 200 == 0:
            print(f"    - Progress: {i}/600")

    end_time = time.time()
    duration = end_time - start_time
    
    print(f"\n[+] Stress test completed in {duration:.2f} seconds.")
    
    with open("logs/test_alerts.json", "r") as f:
        logs = json.load(f)
    
    print(f"[+] Total entries in file: {len(logs)}")
    
    if len(logs) <= 500:
        print("[V] Rotation verified (<= 500 items)")
    else:
        print("[X] Rotation failed!")

if __name__ == "__main__":
    run_stress_test()
