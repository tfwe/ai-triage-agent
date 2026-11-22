"""One fixture per vendor format in the parser layer."""
from __future__ import annotations

from conftest import write
from parsers.asa_parser import parse_asa_logs
from parsers.ecar_parser import parse_all_ecar_logs
from parsers.ids_parser import parse_ids_logs
from parsers.linux_parser import parse_linux_logs
from parsers.win_event_parser import parse_all_windows_logs
from parsers.zeek_parser import parse_all_zeek_logs


def test_linux_syslog_web_and_bash_history(raw_root, out_dir):
    host = raw_root / "WEB-BO-01"
    write(
        str(host / "syslog.log"),
        [
            "May 10 14:02:01 WEB-BO-01 sshd[8123]: Failed password for root from 185.220.101.4 port 44213 ssh2",
            "not a syslog line at all",
        ],
    )
    write(
        str(host / "web_access.log"),
        [
            '203.0.113.9 - - [10/May/2026:13:58:31 -0400] "GET /phpmyadmin/ HTTP/1.1" 404 233 "-" "Nikto/2.5.0"',
        ],
    )
    write(
        str(host / "bash_history" / "deploy"),
        ["#1778420744", "nmap -sS -Pn 10.20.0.0/24"],
    )

    data = parse_linux_logs(str(raw_root), str(out_dir))

    assert set(data) == {"WEB-BO-01"}
    assert len(data["WEB-BO-01"]["syslog"]) == 1
    event = data["WEB-BO-01"]["syslog"][0]
    assert event["process"] == "sshd[8123]"
    assert "Failed password" in event["message"]

    web = data["WEB-BO-01"]["web_access"]
    assert len(web) == 1
    assert web[0]["status_code"] == 404
    # The user agent is the last quoted field, not the referrer.
    assert web[0]["user_agent"] == "Nikto/2.5.0"

    bash = data["WEB-BO-01"]["bash_history"]
    assert len(bash) == 1
    assert bash[0]["username"] == "deploy"
    assert bash[0]["command"].startswith("nmap")
    assert bash[0]["timestamp"] == "1778420744"


def test_linux_parser_derives_hostname_from_dump_root(raw_root, out_dir):
    write(
        str(raw_root / "APP-BO-02" / "syslog.log"),
        ["May 10 12:00:00 APP-BO-02 sshd[1]: Accepted password for ubuntu from 45.83.221.30 port 41220 ssh2"],
    )

    data = parse_linux_logs(str(raw_root), str(out_dir))

    assert list(data) == ["APP-BO-02"]


def test_asa_parser(raw_root, out_dir):
    write(
        str(raw_root / "FW-BO-EDGE" / "asa.log"),
        [
            '<166>May 10 13:58:31 FW-BO-EDGE %ASA-6-106023: Deny tcp src outside:45.83.220.5/49811 '
            "dst inside:10.20.1.10/443 by access-group \"outside_access_in\"",
            "<166>May 10 13:58:32 FW-BO-EDGE %ASA-3-106014: broken line without the rest",
        ],
    )

    data = parse_asa_logs(str(raw_root), str(out_dir))

    assert len(data["FW-BO-EDGE"]) == 2

    # A line that does not match the syslog envelope is skipped, not crashed on.
    write(str(raw_root / "FW-BO-EDGE" / "asa2.log"), ["garbage <not asa>"])
    again = parse_asa_logs(str(raw_root), str(out_dir))
    assert len(again["FW-BO-EDGE"]) == 2


def test_ids_parser_splits_ip_and_port(raw_root, out_dir):
    write(
        str(raw_root / "IDS-BO-EDGE" / "fast.log"),
        [
            "05/10-13:58:33.901257 [**] [1:2024364] ET SCAN Nikto Web App Scan [**] "
            "[Classification: Web Application Attack] [Priority: 1] {TCP} 45.83.220.5:49811 -> 10.20.1.10:443",
            "05/10-13:58:34.000000 [**] [1:2001219] ET SCAN SSH [**] {TCP} 185.220.101.4 -> 10.20.1.11",
            "this line is not a fast log entry",
        ],
    )

    data = parse_ids_logs(str(raw_root), str(out_dir))

    alerts = data["IDS-BO-EDGE"]
    assert len(alerts) == 2
    assert alerts[0]["source_ip"] == "45.83.220.5"
    assert alerts[0]["source_port"] == 49811
    assert alerts[0]["dest_port"] == 443
    assert alerts[0]["priority"] == 1
    # A destination without a port still parses.
    assert alerts[1]["dest_port"] is None


def test_ecar_parser_reads_jsonl(raw_root, out_dir):
    write(
        str(raw_root / "FILE-BO-01" / "ecar.json"),
        [
            '{"timestamp_ms": 1778409821000, "id": "e1", "hostname": "FILE-BO-01", '
            '"object": "PROCESS", "action": "START", "pid": 4412, '
            '"properties": {"command_line": "vssadmin delete shadows /all /quiet"}}',
            '{"timestamp_ms": 1778409822000, "id": "e2", "hostname": "FILE-BO-01", '
            '"object": "PROCESS", "action": "START", "pid": 4413, "properties": {}}',
            '{"timestamp_ms": "not-an-int", "id": "bad", "hostname": "FILE-BO-01", '
            '"object": "PROCESS", "action": "START"}',
        ],
    )

    data = parse_all_ecar_logs(str(raw_root), str(out_dir))
    events = data["FILE-BO-01"]

    assert len(events) == 2
    assert events[0]["id"] == "e1"
    assert events[0]["properties"]["command_line"].startswith("vssadmin")
    # Chronological order is enforced by the parser.
    assert [event["timestamp_ms"] for event in events] == sorted(
        event["timestamp_ms"] for event in events
    )


def test_windows_event_parser(tmp_path, out_dir):
    xml = """<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-05-10T02:21:19.008Z"/>
    <Computer>FILE-BO-01</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="CommandLine">vssadmin delete shadows &amp; exit</Data>
  </EventData>
</Event>
</Events>"""
    path = tmp_path / "raw" / "FILE-BO-01" / "windows"
    path.mkdir(parents=True)
    (path / "events.xml").write_text(xml, encoding="utf-8")

    data = parse_all_windows_logs(str(tmp_path / "raw"), str(out_dir))
    events = data["FILE-BO-01"]

    assert len(events) == 1
    assert events[0]["event_id"] == 4688
    assert events[0]["channel"] == "Security"
    assert events[0]["event_data"]["CommandLine"] == "vssadmin delete shadows & exit"


def test_zeek_parser_builds_sessions(raw_root, out_dir):
    write(
        str(raw_root / "zeek" / "conn.json"),
        [
            '{"ts": 1778422560.0, "uid": "C3bk1", "id.orig_h": "10.20.3.44", "id.orig_p": 50110, '
            '"id.resp_h": "45.83.221.30", "id.resp_p": 443, "proto": "tcp", "orig_bytes": 412, '
            '"resp_bytes": 88, "conn_state": "SF"}'
        ],
    )
    write(
        str(raw_root / "zeek" / "http.json"),
        [
            '{"ts": 1778422561.0, "uid": "C3bk1", "id.orig_h": "10.20.3.44", "id.orig_p": 50110, '
            '"id.resp_h": "45.83.221.30", "id.resp_p": 443, "method": "POST", '
            '"host": "cdn-update-center.net", "uri": "/gate.php", "status_code": 200}'
        ],
    )

    data = parse_all_zeek_logs(str(raw_root), str(out_dir))
    session = data["C3bk1"]

    assert session["connection"]["source_ip"] == "10.20.3.44"
    assert session["connection"]["bytes_sent"] == 412
    assert len(session["http_requests"]) == 1
    assert session["http_requests"][0]["host"] == "cdn-update-center.net"