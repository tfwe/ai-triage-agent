import random

def check_ip_reputation(ip_address: str) -> str:
    """
    Mock Threat Intelligence tool.
    Returns whether an IP is known to be malicious, suspicious, or clean.
    """
    # In a real project, this would hit the VirusTotal or CrowdStrike API
    # For now, we simulate a response
    score = random.randint(0, 100)
    if score > 80:
        return f"CRITICAL: {ip_address} is a known command-and-control server."
    elif score > 50:
        return f"WARNING: {ip_address} has suspicious scanning activity."
    else:
        return f"CLEAN: {ip_address} has no known bad reputation."
