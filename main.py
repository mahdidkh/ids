import os
import sys

# Teacher says: This line helps Python find our 'core' folder
sys.path.append(os.path.join(os.path.dirname(__file__), 'core'))

from sniffer import start_sniffing

if __name__ == "__main__":
    print("""
    =========================================
    🛡️  MINI IDS - STARTING SYSTEM 🛡️
    =========================================
    """)
    try:
        start_sniffing()
    except KeyboardInterrupt:
        print("\n[!] IDS Stopped by User.")
        sys.exit(0)
