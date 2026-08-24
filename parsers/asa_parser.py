import os
import re
import json
from collections import defaultdict
from pydantic import ValidationError
from schemas import AsaEvent

# Matches: <166>May 14 12:00:13 FW-BO-EDGE %ASA-6-302013: Built inbound TCP connection...
ASA_REGEX = re.compile(r"^<\d+>(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+%ASA-\d-(?P<message_id>\d+):\s+(?P<message>.*)$")

def parse_asa_logs(base_dir: str, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    quarantine_path = os.path.join(output_dir, "asa_quarantine.json")
    
    # Grouping by the firewall hostname (e.g., FW-BO-EDGE)
    fw_timelines = defaultdict(list)

    with open(quarantine_path, 'w') as quarantine_file:
        for root, dirs, files in os.walk(base_dir):
            for file in files:
                # Target specific firewall log files; adjust the filename match as needed
                if "FW-BO-EDGE" in root or file.endswith(".log"):
                    file_path = os.path.join(root, file)
                    
                    with open(file_path, 'r', errors='replace') as f:
                        for line in f:
                            line = line.strip()
                            if not line or not line.startswith('<'):
                                continue
                                
                            match = ASA_REGEX.match(line)
                            if match:
                                try:
                                    log = AsaEvent(**match.groupdict())
                                    fw_timelines[log.hostname].append(log.model_dump(mode='json'))
                                except ValidationError as e:
                                    error_record = {
                                        "source_file": file_path,
                                        "raw_data": line,
                                        "error": str(e)
                                    }
                                    quarantine_file.write(json.dumps(error_record) + '\n')

    return fw_timelines

if __name__ == "__main__":
    target_directory = "./data/raw" 
    processed_directory = "./data/processed"
    
    print("Parsing Cisco ASA logs...")
    asa_data = parse_asa_logs(target_directory, processed_directory)
    
    if asa_data:
        output_path = os.path.join(processed_directory, "asa_fw_context.json")
        with open(output_path, "w") as f:
            json.dump(asa_data, f, indent=4)
            
        print(f"Success. Extracted firewall events for {len(asa_data)} host(s).")
