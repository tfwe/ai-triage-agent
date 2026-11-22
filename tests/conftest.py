"""Shared fixtures: tiny per-vendor log trees and a temp triage database."""
from __future__ import annotations

import json
import os
import sqlite3

import pytest

import database


@pytest.fixture()
def raw_root(tmp_path):
    root = tmp_path / "raw"
    root.mkdir()
    return root


@pytest.fixture()
def out_dir(tmp_path):
    out = tmp_path / "processed"
    out.mkdir()
    return out


@pytest.fixture()
def db_path(tmp_path):
    return str(tmp_path / "triage.db")


def write(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for line in lines:
            handle.write(line + "\n")


def make_db(path, endpoint=(), network=(), alerts=(), firewall=()):
    """Create a triage database with exactly the rows a test needs."""
    conn, cursor = database.init_db(path)
    cursor.executemany(
        "INSERT INTO endpoint_events (timestamp, hostname, source, event_data) VALUES (?, ?, ?, ?)",
        endpoint,
    )
    cursor.executemany(
        "INSERT INTO network_traffic (uid, timestamp, src_ip, dest_ip, dest_port, protocol, session_data) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        network,
    )
    cursor.executemany(
        "INSERT INTO alerts (timestamp, sensor, src_ip, dest_ip, alert_data) VALUES (?, ?, ?, ?, ?)",
        alerts,
    )
    cursor.executemany(
        "INSERT INTO firewall_events (timestamp, hostname, message_id, message) VALUES (?, ?, ?, ?)",
        firewall,
    )
    conn.commit()
    conn.close()
    return path


def endpoint_row(host, text, ts="May 10 10:00:00", source="syslog"):
    payload = {"timestamp": ts, "hostname": host, "process": "sshd[1]", "message": text}
    return (ts, host, source, json.dumps(payload))


def alert_row(src_ip, message, dst_ip="10.20.1.10", sensor="IDS-BO-EDGE"):
    payload = {"timestamp": "05/10-10:00:00.000001", "message": message, "source_ip": src_ip}
    return ("05/10-10:00:00.000001", sensor, src_ip, dst_ip, json.dumps(payload))


def session_row(uid, src, dst, port=443, sent=200, received=100, ts=1778421600.0):
    payload = {
        "connection": {
            "timestamp": ts,
            "uid": uid,
            "source_ip": src,
            "dest_ip": dst,
            "dest_port": port,
            "protocol": "tcp",
            "bytes_sent": sent,
            "bytes_received": received,
        },
        "dns_queries": [],
        "http_requests": [],
        "ssl_handshakes": [],
        "files_transferred": [],
        "dhcp_leases": [],
    }
    return (uid, ts, src, dst, port, "tcp", json.dumps(payload))


@pytest.fixture()
def empty_db(db_path):
    return make_db(db_path)