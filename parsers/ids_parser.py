import os
import re
import json
from collections import defaultdict
from pydantic import ValidationError
from schemas import IdsEvent

# Regex for standard Snort/Suricata fast logs
IDS_REGEX = re.compile(
    r"^(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[(?P<sig_id>[^\]]+)\]\s+(?P<message>.*?)\s+\[\*\*\]\s+"
    r"(?:\[Classification:\s+(?P<classification>[^\]]+)\]\s+)?"
    r"(?:\[Priority:\s+(?P<priority>\d+)\]\s+)?"
    r"\{(?P<protocol>\w+)\}\s+(?P<src>\S+)\s+->\s+(?P<dst>\S+)$"
)

def extract_ip_port(ip_port_str):
    """Splits '192.168.1.1:80' into ('192.168.1.1', 80). Handles '192.168.1.1' gracefully."""
    parts = ip_port_str.rsplit(':', 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], int(parts[1])
    return ip_port_str, None

def parse_ids_logs(base_dir: str, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    quarantine_path = os.path.join(output_dir, "ids_quarantine.json")
    
    # We will group by the IDS sensor name (e.g., IDS-BO-EDGE)
    sensor_timelines = defaultdict(list)

    with open(quarantine_path, 'w') as quarantine_file:
        for root, dirs, files in os.walk(base_dir):
            for file in files:
                # Target the fast logs, adjust filename if it differs in your dump
                if "IDS-" in root and file.endswith(".log"):
                    file_path = os.path.join(root, file)
                    sensor_name = os.path.normpath(root).split(os.sep)[-1]
                    
                    print(f"Parsing {file_path}...")
                    
                    with open(file_path, 'r', errors='replace') as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                                
                            match = IDS_REGEX.match(line)
                            if match:
                                data = match.groupdict()
                                
                                # Handle IP/Port splitting
                                data['source_ip'], data['source_port'] = extract_ip_port(data.pop('src'))
                                data['dest_ip'], data['dest_port'] = extract_ip_port(data.pop('dst'))
                                
                                if data.get('priority'):
                                    data['priority'] = int(data['priority'])

                                try:
                                    log = IdsEvent(**data)
                                    sensor_timelines[sensor_name].append(log.model_dump(mode='json'))
                                except ValidationError as e:
                                    error_record = {
                                        "source_file": file_path,
                                        "raw_data": line,
                                        "error": str(e)
                                    }
                                    quarantine_file.write(json.dumps(error_record) + '\n')

    # Sort each sensor's timeline
    for sensor in sensor_timelines:
        sensor_timelines[sensor].sort(key=lambda x: x['timestamp'])

    return sensor_timelines

if __name__ == "__main__":
    target_directory = "./data/raw" 
    processed_directory = "./data/processed"
    
    print("Parsing IDS telemetry...")
    ids_data = parse_ids_logs(target_directory, processed_directory)
    
    if ids_data:
        output_path = os.path.join(processed_directory, "ids_context.json")
        with open(output_path, "w") as f:
            json.dump(ids_data, f, indent=4)
            
        print(f"Success. Mapped alerts across {len(ids_data)} sensor(s).")
