import subprocess
import os

class FirewallManager:
    """Uses 'netsh' to manage Windows Firewall rules."""
    
    @staticmethod
    def block_ip(ip):
        """Adds a block rule for the specified IP."""
        if not ip or not ("." in ip or ":" in ip):
            # Don't try to block non-IP names like "DNS_Server"
            return False
            
        rule_name = f"IDS_BLOCK_{ip}"
        try:
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
            print(f"[*] Firewall: Blocked {ip}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[!] Firewall Error blocking {ip}: {e}")
            print("[TIP] Ensure you are running the terminal/dashboard as ADMINISTRATOR.")
            return False

    @staticmethod
    def unblock_ip(ip):
        """Removes the block rule for the specified IP."""
        rule_name = f"IDS_BLOCK_{ip}"
        try:
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
            print(f"[*] Firewall: Unblocked {ip}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[!] Firewall Error unblocking {ip}: {e}")
            return False

    @staticmethod
    def get_blocked_ips():
        """Attempts to list IPs currently blocked by IDS rules."""
        # This is a bit tricky with netsh, but we can search for our prefix
        try:
            cmd = 'netsh advfirewall firewall show rule name=all'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            lines = result.stdout.splitlines()
            blocked = []
            for line in lines:
                if "IDS_BLOCK_" in line:
                    ip = line.split("IDS_BLOCK_")[-1].strip()
                    if ip not in blocked:
                        blocked.append(ip)
            return blocked
        except Exception:
            return []
