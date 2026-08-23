import json
from pydantic import ValidationError

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

parsed_traffic = parse_zeek_logs("path/to/your/conn.json")
print(f"Successfully parsed {len(parsed_traffic)} valid connections.")
