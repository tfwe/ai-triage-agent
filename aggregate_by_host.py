import os
import json
import sqlite3

def load_json(filepath):
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return json.load(f)
    return {}

def main():
    processed_dir = "./data/processed"
    db_path = os.path.join(processed_dir, "triage.db")
    
    if not os.path.exists(db_path):
        print("Database not found. Run database.py first.")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print("Loading parsed telemetry...")
    win_data = load_json(os.path.join(processed_dir, "windows_event_context.json"))
    lin_data = load_json(os.path.join(processed_dir, "linux_host_context.json"))
    ecar_data = load_json(os.path.join(processed_dir, "ecar_host_context.json"))
    zeek_data = load_json(os.path.join(processed_dir, "zeek_session_context.json"))
    ids_data = load_json(os.path.join(processed_dir, "ids_context.json"))

    print("Ingesting Endpoint Events...")
    endpoint_batch = []
    
    # Windows Events
    for host, events in win_data.items():
        for e in events:
            endpoint_batch.append((e.get('timestamp'), host, "windows_event", json.dumps(e)))
            
    # ECAR Events
    for host, events in ecar_data.items():
        for e in events:
            endpoint_batch.append((str(e.get('timestamp_ms')), host, "ecar", json.dumps(e)))

    # Linux Events
    for host, categories in lin_data.items():
        for source_type in ["syslog", "web_access", "bash_history"]:
            for e in categories.get(source_type, []):
                endpoint_batch.append((e.get('timestamp', 'unknown'), host, source_type, json.dumps(e)))

    if endpoint_batch:
        cursor.executemany('''
            INSERT INTO endpoint_events (timestamp, hostname, source, event_data)
            VALUES (?, ?, ?, ?)
        ''', endpoint_batch)

    print("Ingesting Network Traffic...")
    network_batch = []
    for uid, session in zeek_data.items():
        conn_data = session.get("connection", {})
        if not conn_data:
            continue
            
        network_batch.append((
            uid,
            conn_data.get("ts"),
            conn_data.get("id.orig_h"),
            conn_data.get("id.resp_h"),
            conn_data.get("id.resp_p"),
            conn_data.get("proto"),
            json.dumps(session)
        ))
        
    if network_batch:
        cursor.executemany('''
            INSERT INTO network_traffic (uid, timestamp, src_ip, dest_ip, dest_port, protocol, session_data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', network_batch)

    print("Ingesting IDS Alerts...")
    alert_batch = []
    for sensor, alerts in ids_data.items():
        for a in alerts:
            alert_batch.append((
                a.get('timestamp'),
                sensor,
                a.get('source_ip'),
                a.get('dest_ip'),
                json.dumps(a)
            ))
            
    if alert_batch:
        cursor.executemany('''
            INSERT INTO alerts (timestamp, sensor, src_ip, dest_ip, alert_data)
            VALUES (?, ?, ?, ?, ?)
        ''', alert_batch)

    conn.commit()
    conn.close()
    print("Database ingestion complete.")

if __name__ == "__main__":
    main()
