import requests
import json
import os

class GeoService:
    """Fetches geolocation data for IP addresses."""
    
    def __init__(self, cache_file="logs/geo_cache.json"):
        self.cache_file = cache_file
        self.cache = self._load_cache()
        
    def _load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r") as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_cache(self):
        try:
            with open(self.cache_file, "w") as f:
                json.dump(self.cache, f, indent=4)
        except:
            pass

    def get_location(self, ip):
        """Returns location info for an IP. Uses cache if available."""
        # Clean private IPs
        if ip.startswith(("127.", "192.168.", "10.", "172.16.")):
            return {"country": "Local Network", "city": "Private IP", "countryCode": "LOC"}

        if ip in self.cache:
            return self.cache[ip]

        try:
            # Using ip-api.com (Free for non-commercial, no key needed)
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            data = response.json()
            if data.get("status") == "success":
                location = {
                    "country": data.get("country"),
                    "city": data.get("city"),
                    "countryCode": data.get("countryCode"),
                    "isp": data.get("isp")
                }
                self.cache[ip] = location
                self._save_cache()
                return location
        except Exception:
            # Silently fail for network timeouts
            pass
        
        return {"country": "Unknown", "city": "Unknown", "countryCode": "?"}
