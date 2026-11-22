import json
import os
import sqlite3

DEFAULT_DB_PATH = "data/processed/triage.db"

SCHEMA = {
    "endpoint_events": """
        CREATE TABLE IF NOT EXISTS endpoint_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            hostname TEXT,
            source TEXT,
            event_data JSON
        )""",
    "network_traffic": """
        CREATE TABLE IF NOT EXISTS network_traffic (
            uid TEXT PRIMARY KEY,
            timestamp REAL,
            src_ip TEXT,
            dest_ip TEXT,
            dest_port INTEGER,
            protocol TEXT,
            session_data JSON
        )""",
    "alerts": """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            sensor TEXT,
            src_ip TEXT,
            dest_ip TEXT,
            alert_data JSON
        )""",
    "firewall_events": """
        CREATE TABLE IF NOT EXISTS firewall_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            hostname TEXT,
            message_id TEXT,
            message TEXT
        )""",
}


def init_db(db_path=DEFAULT_DB_PATH):
    """Create the triage schema. Safe to call on an existing database."""
    directory = os.path.dirname(db_path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    for ddl in SCHEMA.values():
        cursor.execute(ddl)
    conn.commit()
    return conn, cursor


def connect(db_path=DEFAULT_DB_PATH, readonly=True):
    """Open the triage database. Read-only by default, mirroring the agent tool."""
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"triage database not found: {db_path}")
    if readonly:
        conn = sqlite3.connect(f"file:{os.path.abspath(db_path)}?mode=ro", uri=True)
    else:
        conn = sqlite3.connect(db_path)
    return conn


def query(sql, params=(), db_path=DEFAULT_DB_PATH):
    """Run a parameterised query and return rows as dictionaries."""
    conn = connect(db_path)
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(sql, params)
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def _load_json(path):
    if not os.path.exists(path):
        return None
    with open(path, "r") as handle:
        return json.load(handle)


def ingest_processed(processed_dir="data/processed", db_path=DEFAULT_DB_PATH, reset=False):
    """Load the parser output in ``processed_dir`` into the triage database.

    Returns a dict of per-table row counts actually inserted.
    """
    if reset and os.path.exists(db_path):
        os.remove(db_path)
    conn, cursor = init_db(db_path)
    counts = {
        "endpoint_events": 0,
        "network_traffic": 0,
        "alerts": 0,
        "firewall_events": 0,
    }

    try:
        endpoint_batch = []

        win_data = _load_json(os.path.join(processed_dir, "windows_event_context.json")) or {}
        for host, events in win_data.items():
            for event in events:
                endpoint_batch.append(
                    (event.get("timestamp"), host, "windows_event", json.dumps(event))
                )

        ecar_data = _load_json(os.path.join(processed_dir, "ecar_host_context.json")) or {}
        for host, events in ecar_data.items():
            for event in events:
                endpoint_batch.append(
                    (str(event.get("timestamp_ms")), host, "ecar", json.dumps(event))
                )

        lin_data = _load_json(os.path.join(processed_dir, "linux_host_context.json")) or {}
        for host, categories in lin_data.items():
            for source_type in ("syslog", "web_access", "bash_history"):
                for event in categories.get(source_type, []):
                    endpoint_batch.append(
                        (
                            str(event.get("timestamp", "unknown")),
                            host,
                            source_type,
                            json.dumps(event),
                        )
                    )

        if endpoint_batch:
            cursor.executemany(
                "INSERT INTO endpoint_events (timestamp, hostname, source, event_data) "
                "VALUES (?, ?, ?, ?)",
                endpoint_batch,
            )
            counts["endpoint_events"] = len(endpoint_batch)

        zeek_data = _load_json(os.path.join(processed_dir, "zeek_session_context.json")) or {}
        network_batch = []
        for uid, session in zeek_data.items():
            connection = session.get("connection") or {}
            if not connection:
                continue

            # Pydantic dumps here use field names (timestamp, source_ip, ...)
            # while raw Zeek uses aliases (ts, id.orig_h, ...). Accept both.
            def pick(*names):
                for name in names:
                    if name in connection:
                        return connection[name]
                return None

            network_batch.append(
                (
                    uid,
                    pick("timestamp", "ts"),
                    pick("source_ip", "id.orig_h"),
                    pick("dest_ip", "id.resp_h"),
                    pick("dest_port", "id.resp_p"),
                    pick("protocol", "proto"),
                    json.dumps(session),
                )
            )
        if network_batch:
            cursor.executemany(
                "INSERT OR REPLACE INTO network_traffic "
                "(uid, timestamp, src_ip, dest_ip, dest_port, protocol, session_data) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                network_batch,
            )
            counts["network_traffic"] = len(network_batch)

        ids_data = _load_json(os.path.join(processed_dir, "ids_context.json")) or {}
        alert_batch = []
        for sensor, alerts in ids_data.items():
            for alert in alerts:
                alert_batch.append(
                    (
                        alert.get("timestamp"),
                        sensor,
                        alert.get("source_ip"),
                        alert.get("dest_ip"),
                        json.dumps(alert),
                    )
                )
        if alert_batch:
            cursor.executemany(
                "INSERT INTO alerts (timestamp, sensor, src_ip, dest_ip, alert_data) "
                "VALUES (?, ?, ?, ?, ?)",
                alert_batch,
            )
            counts["alerts"] = len(alert_batch)

        asa_data = _load_json(os.path.join(processed_dir, "asa_fw_context.json")) or {}
        fw_batch = []
        for hostname, events in asa_data.items():
            for event in events:
                fw_batch.append(
                    (
                        event.get("timestamp"),
                        event.get("hostname", hostname),
                        event.get("message_id"),
                        event.get("message"),
                    )
                )
        if fw_batch:
            cursor.executemany(
                "INSERT INTO firewall_events (timestamp, hostname, message_id, message) "
                "VALUES (?, ?, ?, ?)",
                fw_batch,
            )
            counts["firewall_events"] = len(fw_batch)

        conn.commit()
    finally:
        conn.close()
    return counts


if __name__ == "__main__":
    init_db()
    print("Initialised the triage database schema.")