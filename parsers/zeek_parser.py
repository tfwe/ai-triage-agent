import os
import json
from pydantic import ValidationError
from collections import defaultdict
from schemas import (
    ZeekConnection, ZeekDNS, ZeekHTTP, ZeekSSL, ZeekFiles,
    ZeekDHCP, ZeekX509, ZeekPE, ZeekOCSP
)

# Map filenames to their respective schemas
SCHEMA_MAP = {
    "conn.json": ZeekConnection,
    "dns.json": ZeekDNS,
    "http.json": ZeekHTTP,
    "ssl.json": ZeekSSL,
    "files.json": ZeekFiles,
    "dhcp.json": ZeekDHCP,
    "x509.json": ZeekX509,
    "pe.json": ZeekPE,
    "ocsp.json": ZeekOCSP
}

def parse_and_aggregate_zeek(data_dir, output_dir):
    # Session tracker keyed by connection UID
    sessions = defaultdict(lambda: {
        "connection": None,
        "dns_queries": [],
        "http_requests": [],
        "ssl_handshakes": [],
        "files_transferred": []
    })
    
    os.makedirs(output_dir, exist_ok=True)
    quarantine_path = os.path.join(output_dir, "quarantine.json")
    
    with open(quarantine_path, 'w') as quarantine_file:
        for filename, schema in SCHEMA_MAP.items():
            file_path = os.path.join(data_dir, filename)
            
            if not os.path.exists(file_path):
                continue
                
            print(f"Parsing {filename}...")
            
            with open(file_path, 'r') as f:
                for line in f:
                    try:
                        raw_log = json.loads(line)
                        validated_log = schema(**raw_log)
                        
                        # Route log to the correct session based on schema type
                        uid = getattr(validated_log, 'uid', None)
                        
                        if uid:
                            if isinstance(validated_log, ZeekConnection):
                                sessions[uid]["connection"] = validated_log.model_dump(mode='json')
                            elif isinstance(validated_log, ZeekDNS):
                                sessions[uid]["dns_queries"].append(validated_log.model_dump(mode='json'))
                            elif isinstance(validated_log, ZeekHTTP):
                                sessions[uid]["http_requests"].append(validated_log.model_dump(mode='json'))
                            elif isinstance(validated_log, ZeekSSL):
                                sessions[uid]["ssl_handshakes"].append(validated_log.model_dump(mode='json'))
                        
                        # Files use fuid and map to multiple conn_uids
                        elif isinstance(validated_log, ZeekFiles):
                            for c_uid in validated_log.conn_uids:
                                sessions[c_uid]["files_transferred"].append(validated_log.model_dump(mode='json'))
                                
                    except ValidationError as e:
                        # Dead-letter queue: write bad logs to quarantine instead of dropping
                        error_record = {
                            "source_file": filename,
                            "raw_data": raw_log if 'raw_log' in locals() else line.strip(),
                            "error": str(e)
                        }
                        quarantine_file.write(json.dumps(error_record) + '\n')

    return sessions

if __name__ == "__main__":
    data_directory = "./data/raw/ZEEK-BO-CORE"
    processed_directory = "./data/processed"
    
    print("Starting Zeek log aggregation...")
    session_data = parse_and_aggregate_zeek(data_directory, processed_directory)
    
    # Save the aggregated sessions
    output_path = os.path.join(processed_directory, "session_context.json")
    with open(output_path, "w") as f:
        json.dump(session_data, f, indent=4)
        
    print(f"Success. Aggregated logs into {len(session_data)} distinct sessions.")
    print(f"Aggregated data saved to {output_path}")
    print(f"Malformed logs quarantined in {os.path.join(processed_directory, 'quarantine.json')}")
