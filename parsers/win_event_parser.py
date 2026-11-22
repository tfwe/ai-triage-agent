import os
import json
import xml.etree.ElementTree as ET
from collections import defaultdict
from pydantic import ValidationError
try:  # imported as a package module
    from .schemas import WinEvent
except ImportError:  # executed as a plain script
    from schemas import WinEvent

def strip_namespace(tag):
    # Windows XML tags look like {http://schemas.microsoft.com/...}Event
    return tag.split('}', 1)[1] if '}' in tag else tag

def parse_xml_events(file_path: str):
    events = []
    tree = ET.parse(file_path)
    root = tree.getroot()

    for event in root.findall('.//*'):
        if strip_namespace(event.tag) == 'Event':
            system_tag = None
            event_data_tag = None
            
            for child in event:
                clean_tag = strip_namespace(child.tag)
                if clean_tag == 'System':
                    system_tag = child
                elif clean_tag == 'EventData':
                    event_data_tag = child

            if system_tag is None:
                continue

            event_id = None
            timestamp = None
            hostname = "Unknown"
            channel = "Unknown"

            # Extract System Metadata safely by iterating and stripping namespaces
            for sys_child in system_tag:
                sys_tag = strip_namespace(sys_child.tag)
                if sys_tag == 'EventID':
                    event_id = sys_child.text
                elif sys_tag == 'TimeCreated':
                    timestamp = sys_child.attrib.get('SystemTime')
                elif sys_tag == 'Computer':
                    hostname = sys_child.text
                elif sys_tag == 'Channel':
                    channel = sys_child.text

            if not event_id or not timestamp:
                continue

            # Extract EventData payload safely
            event_data = {}
            if event_data_tag is not None:
                for data in event_data_tag:
                    if strip_namespace(data.tag) == 'Data':
                        key = data.attrib.get('Name', 'Unknown')
                        val = data.text
                        event_data[key] = val

            raw_dict = {
                "timestamp": timestamp,
                "event_id": int(event_id),
                "hostname": hostname,
                "channel": channel,
                "event_data": event_data
            }

            events.append(raw_dict)
            
    return events

def parse_all_windows_logs(base_dir: str, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    host_timelines = defaultdict(list)

    for root_dir, _, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.xml'):
                file_path = os.path.join(root_dir, file)
                print(f"Parsing {file_path}...")
                
                raw_events = parse_xml_events(file_path)
                
                for raw_log in raw_events:
                    try:
                        validated_log = WinEvent(**raw_log)
                        host_timelines[validated_log.hostname].append(validated_log.model_dump(mode='json'))
                    except ValidationError as e:
                        # Handle validation errors silently or write to quarantine
                        continue

    # Sort each host's timeline
    for host in host_timelines:
        host_timelines[host].sort(key=lambda x: x['timestamp'])

    return host_timelines

if __name__ == "__main__":
    target_directory = "./data/raw" 
    processed_directory = "./data/processed"
    
    print(f"Starting bulk XML telemetry parsing from {target_directory}...")
    host_data = parse_all_windows_logs(target_directory, processed_directory)
    
    if host_data:
        output_path = os.path.join(processed_directory, "windows_event_context.json")
        with open(output_path, "w") as f:
            json.dump(host_data, f, indent=4)
            
        print(f"Success. Mapped Windows Events across {len(host_data)} host(s).")
