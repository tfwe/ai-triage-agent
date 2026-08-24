import sqlite3
import json
import os
import requests
import re

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


def query_triage_db(sql_query: str) -> str:
    # Hard guardrail to stop schema hallucinations
    if re.search(r'(src_ip|dest_ip)\s*=\s*\'[a-zA-Z]', sql_query):
        return "ERROR: Schema violation. You attempted to search for a string hostname in an IP address column (src_ip or dest_ip). Rewrite your query to search the 'hostname' or payload columns instead."
        
    db_path = os.path.abspath("data/processed/triage.db")
    
    if not os.path.exists(db_path):
        return "ERROR: Database file not found."

    try:
        # Force read-only mode via URI so the LLM can't modify or delete data
        uri = f"file:{db_path}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        cursor = conn.cursor()
        
        cursor.execute(sql_query)
        
        # Grab column names to map the data cleanly
        columns = [desc[0] for desc in cursor.description] if cursor.description else []
        
        # Force a hard cap on returned rows to protect the context window
        MAX_ROWS = 15
        rows = cursor.fetchmany(MAX_ROWS + 1)
        
        results = [dict(zip(columns, row)) for row in rows[:MAX_ROWS]]
        conn.close()
        
        if not results:
            return "Query executed successfully, but returned 0 rows."
            
        output = json.dumps(results, indent=2)
        if len(rows) > MAX_ROWS:
            output += f"\n\n[WARNING] Query returned more than {MAX_ROWS} rows. Output truncated. Refine your WHERE clause to be more specific."
            
        return output

    except sqlite3.Error as e:
        # Feed the syntax error back to the LLM so it can fix its own mistake
        return f"SQL Error: {e}"
