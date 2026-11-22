import os
import re
import json
from collections import defaultdict
from pydantic import ValidationError
try:  # imported as a package module
    from .schemas import SyslogEvent, WebAccessEvent, BashHistoryEvent
except ImportError:  # executed as a plain script
    from schemas import SyslogEvent, WebAccessEvent, BashHistoryEvent

# Standard BSD syslog format: "May 10 14:02:01 WEB-BO-01 sshd[1234]: Failed password..."
SYSLOG_REGEX = re.compile(r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>[^:]+):\s+(?P<message>.*)$")

# Standard Combined Log Format for Apache/Nginx:
# 1.2.3.4 - - [10/May/2026:13:58:31 -0400] "GET /path HTTP/1.1" 404 233 "-" "UA/1.0"
# The user agent is the LAST quoted field, not the first one after the status.
WEB_REGEX = re.compile(
    r'^(?P<source_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" '
    r'(?P<status_code>\d{3}) \S+ "[^"]*" "(?P<user_agent>[^"]*)"\s*$'
)

def parse_linux_logs(base_dir: str, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    host_timelines = defaultdict(lambda: {"syslog": [], "web_access": [], "bash_history": []})

    for root, dirs, files in os.walk(base_dir):
        # Hostname is the first path component under the dump root
        # (e.g. data/raw/WEB-BO-01/syslog.log -> WEB-BO-01)
        relative = os.path.relpath(root, base_dir)
        hostname = "Unknown" if relative == os.curdir else relative.split(os.sep)[0]

        for file in files:
            file_path = os.path.join(root, file)

            if file == "syslog.log":
                with open(file_path, 'r') as f:
                    for line in f:
                        match = SYSLOG_REGEX.match(line.strip())
                        if match:
                            try:
                                log = SyslogEvent(**match.groupdict())
                                host_timelines[hostname]["syslog"].append(log.model_dump(mode='json'))
                            except ValidationError:
                                continue

            elif file == "web_access.log":
                with open(file_path, 'r') as f:
                    for line in f:
                        match = WEB_REGEX.match(line.strip())
                        if match:
                            try:
                                data = match.groupdict()
                                data['status_code'] = int(data['status_code'])
                                log = WebAccessEvent(**data)
                                host_timelines[hostname]["web_access"].append(log.model_dump(mode='json'))
                            except ValidationError:
                                continue

            # Bash history files usually don't have extensions, or are named after the user
            elif "bash_history" in root:
                username = file
                
                # Filter out Alternate Data Streams and hidden files
                if username.endswith(":Zone.Identifier") or username.startswith("."):
                    continue

                with open(file_path, 'r', errors='replace') as f:
                    current_timestamp = None
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        
                        # Catch epoch timestamps
                        if line.startswith("#") and line[1:].isdigit():
                            current_timestamp = line[1:]
                        else:
                            # It's a command, pair it with the stored timestamp
                            log_data = {
                                "hostname": hostname,
                                "username": username,
                                "command": line
                            }
                            if current_timestamp:
                                log_data["timestamp"] = current_timestamp
                                current_timestamp = None # Reset for the next command
                                
                            try:
                                log = BashHistoryEvent(**log_data)
                                host_timelines[hostname]["bash_history"].append(log.model_dump(mode='json'))
                            except ValidationError:
                                continue

    return host_timelines

if __name__ == "__main__":
    target_directory = "./data/raw" 
    processed_directory = "./data/processed"
    
    print("Parsing Linux text logs...")
    linux_data = parse_linux_logs(target_directory, processed_directory)
    
    if linux_data:
        output_path = os.path.join(processed_directory, "linux_host_context.json")
        with open(output_path, "w") as f:
            json.dump(linux_data, f, indent=4)
            
        print("Success.")
