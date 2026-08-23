import os
import json
from pydantic import ValidationError
from collections import defaultdict
from schemas import ZeekConnection

def parse_zeek_logs(file_path):
    valid_logs = []
    with open(file_path, 'r') as f:
        for line in f:
            try:
                raw_log = json.loads(line)
                validated_log = ZeekConnection(**raw_log)
                valid_logs.append(validated_log)
            except ValidationError:
                # Drop malformed logs silently to keep the pipeline moving
                continue
    return valid_logs

def aggregate_by_host(valid_logs):
    # Group by source_ip
    host_activity = defaultdict(lambda: {
        "destinations": set(),
        "ports_accessed": set(),
        "total_bytes_sent": 0,
        "total_bytes_received": 0,
        "connection_count": 0
    })

    for log in valid_logs:
        ip = str(log.source_ip)
        host_activity[ip]["destinations"].add(str(log.dest_ip))
        host_activity[ip]["ports_accessed"].add(log.dest_port)
        host_activity[ip]["total_bytes_sent"] += log.bytes_sent
        host_activity[ip]["total_bytes_received"] += log.bytes_received
        host_activity[ip]["connection_count"] += 1

    # Convert sets to lists so we can serialize to JSON
    for ip, data in host_activity.items():
        data["destinations"] = list(data["destinations"])
        data["ports_accessed"] = list(data["ports_accessed"])

    return host_activity

if __name__ == "__main__":
    # 1. Ingest and validate
    print("Parsing raw Zeek logs...")
    parsed_traffic = parse_zeek_logs("./data/raw/ZEEK-BO-CORE/conn.json")
    
    # 2. Aggregate by host
    print("Aggregating traffic by source IP...")
    batched_context = aggregate_by_host(parsed_traffic)
    
    # 3. Save to processed folder
    output_path = "./data/processed/host_activity_context.json"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, "w") as f:
        json.dump(batched_context, f, indent=4)
        
    print(f"Success. Compressed {len(parsed_traffic)} logs into {len(batched_context)} host summaries.")
    print(f"Saved to {output_path}")
