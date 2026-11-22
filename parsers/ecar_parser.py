import os
import json
from pydantic import ValidationError
from collections import defaultdict
try:  # imported as a package module
    from .schemas import EcarEvent
except ImportError:  # executed as a plain script
    from schemas import EcarEvent

def parse_all_ecar_logs(base_dir: str, output_dir: str):
    if not os.path.exists(base_dir):
        print(f"Directory not found: {base_dir}")
        return None

    os.makedirs(output_dir, exist_ok=True)
    quarantine_path = os.path.join(output_dir, "ecar_quarantine.json")
    
    host_timelines = defaultdict(list)

    with open(quarantine_path, 'w') as quarantine_file:
        # Walk through all directories looking for ecar.json
        for root, dirs, files in os.walk(base_dir):
            for file in files:
                if file == "ecar.json":
                    file_path = os.path.join(root, file)
                    print(f"Parsing {file_path}...")
                    
                    with open(file_path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                raw_log = json.loads(line)
                                validated_log = EcarEvent(**raw_log)
                                
                                # Drop the event into the correct host's bucket
                                hostname = validated_log.hostname
                                host_timelines[hostname].append(validated_log.model_dump(mode='json'))

                            except ValidationError as e:
                                error_record = {
                                    "source_file": file_path,
                                    "raw_data": raw_log if 'raw_log' in locals() else line,
                                    "error": str(e)
                                }
                                quarantine_file.write(json.dumps(error_record) + '\n')

    # Sort each host's timeline chronologically so the LLM doesn't get confused
    for host in host_timelines:
        host_timelines[host].sort(key=lambda x: x['timestamp_ms'])

    return host_timelines

if __name__ == "__main__":
    # Point this to the root of the EvidenceForge dump
    target_directory = "./data/raw" 
    processed_directory = "./data/processed"
    
    print(f"Starting bulk EDR telemetry parsing from {target_directory}...")
    host_data = parse_all_ecar_logs(target_directory, processed_directory)
    
    if host_data:
        output_path = os.path.join(processed_directory, "ecar_host_context.json")
        with open(output_path, "w") as f:
            json.dump(host_data, f, indent=4)
            
        print(f"Success. Mapped and sorted events across {len(host_data)} distinct host(s).")
