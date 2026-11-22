"""Schema creation, ingestion from parser output, and read-only access."""
from __future__ import annotations

import json
import sqlite3

import pytest

import database


def seed_processed(processed_dir):
    payloads = {
        "windows_event_context.json": {
            "FILE-BO-01": [
                {"timestamp": "2026-05-10T02:21:19.008Z", "event_id": 4688, "hostname": "FILE-BO-01",
                 "channel": "Security", "event_data": {"CommandLine": "vssadmin delete shadows"}}
            ]
        },
        "ecar_host_context.json": {
            "FILE-BO-01": [
                {"timestamp_ms": 1778409821000, "id": "e1", "hostname": "FILE-BO-01",
                 "object": "PROCESS", "action": "START", "properties": {}}
            ]
        },
        "linux_host_context.json": {
            "WEB-BO-01": {
                "syslog": [{"timestamp": "May 10 14:02:01", "hostname": "WEB-BO-01",
                            "process": "sshd[1]", "message": "Failed password for root"}],
                "web_access": [],
                "bash_history": [{"hostname": "WEB-BO-01", "username": "root",
                                  "command": "nmap -sS 10.0.0.0/24", "timestamp": "1778420744"}],
            }
        },
        "zeek_session_context.json": {
            "C3bk1": {
                "connection": {
                    "timestamp": 1778422560.0, "uid": "C3bk1", "source_ip": "10.20.3.44",
                    "dest_ip": "45.83.221.30", "dest_port": 443, "protocol": "tcp",
                    "bytes_sent": 412, "bytes_received": 88,
                },
                "http_requests": [],
            }
        },
        "ids_context.json": {
            "IDS-BO-EDGE": [
                {"timestamp": "05/10-13:58:33.901257", "sig_id": "1:2024364",
                 "message": "ET SCAN Nikto", "protocol": "TCP", "source_ip": "45.83.220.5",
                 "dest_ip": "10.20.1.10", "dest_port": 443}
            ]
        },
        "asa_fw_context.json": {
            "FW-BO-EDGE": [
                {"timestamp": "May 10 13:58:31", "hostname": "FW-BO-EDGE",
                 "message_id": "106023", "message": "Deny tcp src outside:45.83.220.5"}
            ]
        },
    }
    for name, payload in payloads.items():
        with open(processed_dir / name, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)


def test_ingest_maps_every_table(tmp_path, db_path):
    processed = tmp_path / "processed"
    processed.mkdir()
    seed_processed(processed)

    counts = database.ingest_processed(str(processed), db_path=db_path, reset=True)

    assert counts["endpoint_events"] == 4
    assert counts["network_traffic"] == 1
    assert counts["alerts"] == 1
    assert counts["firewall_events"] == 1

    session = database.query("SELECT * FROM network_traffic", db_path=db_path)[0]
    # Zeek sessions are dumped with pydantic field names, not raw aliases.
    assert session["src_ip"] == "10.20.3.44"
    assert session["dest_ip"] == "45.83.221.30"
    assert session["dest_port"] == 443


def test_ingest_is_repeatable_with_reset(tmp_path, db_path):
    processed = tmp_path / "processed"
    processed.mkdir()
    seed_processed(processed)

    database.ingest_processed(str(processed), db_path=db_path, reset=True)
    database.ingest_processed(str(processed), db_path=db_path, reset=True)

    assert database.query("SELECT count(*) AS c FROM endpoint_events", db_path=db_path)[0]["c"] == 4


def test_readonly_connection_refuses_writes(tmp_path, db_path):
    database.init_db(db_path)[0].close()

    conn = database.connect(db_path)
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("INSERT INTO alerts (timestamp) VALUES ('x')")


def test_missing_database_raises_clear_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        database.connect(str(tmp_path / "nope.db"))