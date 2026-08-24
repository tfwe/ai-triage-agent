import sqlite3
import json
import os

def init_db(db_path="data/processed/triage.db"):
    # Ensure the directory exists so it doesn't crash on a fresh clone
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS endpoint_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            hostname TEXT,
            source TEXT,
            event_data JSON
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS network_traffic (
            uid TEXT PRIMARY KEY,
            timestamp REAL,
            src_ip TEXT,
            dest_ip TEXT,
            dest_port INTEGER,
            protocol TEXT,
            session_data JSON
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            sensor TEXT,
            src_ip TEXT,
            dest_ip TEXT,
            alert_data JSON
        )
    ''')
    
    conn.commit()
    return conn, cursor

