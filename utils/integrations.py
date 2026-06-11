import logging
import requests

logger = logging.getLogger(__name__)

class IntegrationsManager:
    def __init__(self, config):
        self.config = config
        self.virustotal_url = "https://www.virustotal.com/api/v3"
        self.abuseipdb_url = "https://api.abuseipdb.com/api/v2"

    def check_virustotal_ip(self, ip):
        try:
            api_key = self.config.get("virustotal_api", "")
            if not api_key:
                return {"error": "VirusTotal API key not configured"}
            
            headers = {"x-apikey": api_key}
            url = f"{self.virustotal_url}/ip_addresses/{ip}"
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data.get("data", {}).get("attributes", {})
        except Exception as e:
            logger.error(f"VirusTotal check failed: {e}")
            return {"error": str(e)}

    def check_abuseipdb_ip(self, ip):
        try:
            api_key = self.config.get("abuseipdb_api", "")
            if not api_key:
                return {"error": "AbuseIPDB API key not configured"}
            
            headers = {"Key": api_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": "90"}
            url = f"{self.abuseipdb_url}/check"
            response = requests.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data.get("data", {})
        except Exception as e:
            logger.error(f"AbuseIPDB check failed: {e}")
            return {"error": str(e)}
