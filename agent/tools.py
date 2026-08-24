import os
import requests

from config import settings 

def check_ip_reputation(ip_address: str) -> str:
    if not settings.abuseipdb_api_key:
        raise ValueError("ABUSEIPDB_API_KEY environment variable is missing.")

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": settings.abuseipdb_api_key
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90",
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        response.raise_for_status()
        data = response.json().get("data", {})
        
        score = data.get("abuseConfidenceScore", 0)
        country = data.get("countryCode", "Unknown")

        if score > 80:
            return f"CRITICAL: {ip_address} ({country}) - Abuse Confidence: {score}%"
        elif score > 20:
            return f"WARNING: {ip_address} ({country}) - Abuse Confidence: {score}%"
        else:
            return f"CLEAN: {ip_address} ({country}) - Abuse Confidence: {score}%"

    except requests.RequestException as err:
        return f"ERROR querying threat intelligence: {err}"
