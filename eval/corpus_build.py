"""Build the triage database from the synthetic evidence corpus.

Pipeline, all deterministic and offline:

    eval/corpus/scenarios.json  (structured events, one block per alert)
        -> data/raw/<host>/...   (vendor-format log lines: syslog, combined
                                  web log, bash_history, ecar.json, Windows
                                  event XML, Zeek JSONL, IDS fast log, ASA syslog)
        -> parsers/*.py          (the real parsers, not a shortcut)
        -> data/processed/*.json (parser output)
        -> data/processed/triage.db (what the agent queries)

Run it with ``python -m eval.corpus_build``. Nothing here touches the network,
so the corpus can be rebuilt on a laptop with no model installed.
"""
from __future__ import annotations

import json
import os
import shutil
from collections import defaultdict

import database
from parsers.asa_parser import parse_asa_logs
from parsers.ecar_parser import parse_all_ecar_logs
from parsers.ids_parser import parse_ids_logs
from parsers.linux_parser import parse_linux_logs
from parsers.win_event_parser import parse_all_windows_logs
from parsers.zeek_parser import parse_all_zeek_logs

SCENARIOS_PATH = "eval/corpus/scenarios.json"
RAW_ROOT = "data/raw"
PROCESSED_DIR = "data/processed"
DB_PATH = "data/processed/triage.db"
CASES_ROOT = "data/cases"


def load_scenarios(path: str = SCENARIOS_PATH) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


_TS_FORMATS = (
    "%b %d %H:%M:%S",            # syslog / ASA
    "%m/%d-%H:%M:%S.%f",         # snort fast log
    "%Y-%m-%dT%H:%M:%S.%fZ",     # Windows Event XML
    "%Y-%m-%dT%H:%M:%S",         # generic ISO
)


def _shift_timestamp(value, seconds: float):
    """Add ``seconds`` to a timestamp, keeping its original format."""
    if isinstance(value, (int, float)):
        return round(value + seconds, 6)
    from datetime import datetime, timedelta
    import warnings

    with warnings.catch_warnings():
        # Some vendor formats omit the year; the corpus uses a fixed campaign
        # date, so the default year is irrelevant here.
        warnings.simplefilter("ignore", DeprecationWarning)
        for fmt in _TS_FORMATS:
            try:
                parsed = datetime.strptime(value, fmt)
            except ValueError:
                continue
            shifted = parsed + timedelta(seconds=seconds)
            return shifted.strftime(fmt)
    return value


def expand(events: list[dict]) -> list[dict]:
    """Expand ``repeat`` templates into concrete, distinct events.

    ``{i}`` in any string field, plus ``ts_step`` / ``port_step``, lets one
    line in the scenario file stand for a brute-force burst without writing
    forty near-identical JSON objects by hand.
    """
    out: list[dict] = []
    for event in events:
        repeat = int(event.get("repeat", 1))
        for index in range(repeat):
            clone = json.loads(json.dumps(event))
            clone.pop("repeat", None)
            ts_step = clone.pop("ts_step", None)
            port_step = clone.pop("port_step", None)
            if ts_step is not None:
                clone["ts"] = _shift_timestamp(clone["ts"], index * ts_step)
            if port_step is not None:
                for port_field in ("sport", "orig_p"):
                    if isinstance(clone.get(port_field), int):
                        clone[port_field] += index * port_step
            for key, value in list(clone.items()):
                if isinstance(value, str):
                    clone[key] = value.replace("{i}", str(index + 1))
            out.append(clone)
    return out


def _write(path: str, lines: list[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for line in lines:
            handle.write(line + "\n")


def _web_line(event: dict) -> str:
    return (
        f'{event["ip"]} - - [{event["ts"]}] "{event["method"]} {event["path"]} '
        f'HTTP/1.1" {event["status"]} {event.get("bytes", 512)} "-" "{event["ua"]}"'
    )


def _ids_line(event: dict) -> str:
    classification = event.get("cls", "Misc activity")
    return (
        f'{event["ts"]} [**] [{event["sig"]}] {event["msg"]} [**] '
        f'[Classification: {classification}] [Priority: {event.get("pr", 3)}] '
        f'{{{event["proto"]}}} {event["source_ip"]}:{event["sport"]} -> '
        f'{event["dest_ip"]}:{event["dport"]}'
    )


def _asa_line(event: dict) -> str:
    return (
        f'<166>{event["ts"]} {event.get("host", "FW-BO-EDGE")} '
        f'%ASA-{event.get("severity", 6)}-{event["msg_id"]}: {event["msg"]}'
    )


def _win_event_xml(event: dict) -> str:
    from xml.sax.saxutils import escape, quoteattr

    data = "".join(
        f'<Data Name={quoteattr(str(key))}>{escape(str(value))}</Data>'
        for key, value in event.get("data", {}).items()
    )
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        f"<System><EventID>{event['event_id']}</EventID>"
        f'<TimeCreated SystemTime="{event["ts"]}"/>'
        f"<Computer>{escape(str(event['host']))}</Computer>"
        f"<Channel>{escape(str(event.get('channel', 'Security')))}</Channel></System>"
        f"<EventData>{data}</EventData></Event>"
    )


def _ecar_line(event: dict) -> str:
    record = {
        "timestamp_ms": event["ts_ms"],
        "id": event["id"],
        "hostname": event["host"],
        "object": event["object"],
        "action": event["action"],
    }
    for optional in ("actorID", "objectID", "pid", "ppid", "principal"):
        if optional in event:
            record[optional] = event[optional]
    record["properties"] = event.get("props", {})
    return json.dumps(record)


def render(events: list[dict], raw_root: str = RAW_ROOT) -> dict[str, int]:
    """Write the vendor-format files. Returns a count of lines per vendor."""
    lines: dict[str, list[str]] = defaultdict(list)
    xml_events: dict[str, list[str]] = defaultdict(list)

    for event in events:
        source = event["src"]
        if source == "syslog":
            lines[f"{raw_root}/{event['host']}/syslog.log"].append(
                f'{event["ts"]} {event["host"]} {event["proc"]}: {event["msg"]}'
            )
        elif source == "web":
            lines[f"{raw_root}/{event['host']}/web_access.log"].append(_web_line(event))
        elif source == "bash":
            lines[f"{raw_root}/{event['host']}/bash_history/{event['user']}"].append(
                f'#{event["ts"]}\n{event["cmd"]}'
            )
        elif source == "ecar":
            lines[f"{raw_root}/{event['host']}/ecar.json"].append(_ecar_line(event))
        elif source == "win":
            xml_events[event["host"]].append(_win_event_xml(event))
        elif source == "zeek_conn":
            record = {
                "ts": event["ts"],
                "uid": event["uid"],
                "id.orig_h": event["orig_h"],
                "id.orig_p": event["orig_p"],
                "id.resp_h": event["resp_h"],
                "id.resp_p": event["resp_p"],
                "proto": event.get("proto", "tcp"),
                "orig_bytes": event.get("orig_bytes", 0),
                "resp_bytes": event.get("resp_bytes", 0),
                "conn_state": event.get("state", "SF"),
            }
            lines[f"{raw_root}/zeek/conn.json"].append(json.dumps(record))
        elif source == "zeek_http":
            record = {
                "ts": event["ts"],
                "uid": event["uid"],
                "id.orig_h": event["orig_h"],
                "id.orig_p": event["orig_p"],
                "id.resp_h": event["resp_h"],
                "id.resp_p": event["resp_p"],
                "method": event["method"],
                "host": event["vh"],
                "uri": event["uri"],
                "user_agent": event.get("ua", "-"),
                "status_code": event.get("status", 200),
            }
            lines[f"{raw_root}/zeek/http.json"].append(json.dumps(record))
        elif source == "ids":
            sensor = event.get("sensor", "IDS-BO-EDGE")
            lines[f"{raw_root}/{sensor}/fast.log"].append(_ids_line(event))
        elif source == "asa":
            lines[f"{raw_root}/FW-BO-EDGE/asa.log"].append(_asa_line(event))
        else:
            raise ValueError(f"unknown telemetry source: {source!r}")

    for path, body in lines.items():
        _write(path, body)
    for host, xml_body in xml_events.items():
        _write(
            f"{raw_root}/{host}/windows/events.xml",
            ["<Events>" + "".join(xml_body) + "</Events>"],
        )
    return {path: len(body) for path, body in lines.items()}


def parse_all(raw_root: str = RAW_ROOT, processed_dir: str = PROCESSED_DIR) -> dict:
    """Run every vendor parser over the rendered logs."""
    os.makedirs(processed_dir, exist_ok=True)
    outputs = {
        "asa_fw_context.json": parse_asa_logs(raw_root, processed_dir),
        "ecar_host_context.json": parse_all_ecar_logs(raw_root, processed_dir),
        "ids_context.json": parse_ids_logs(raw_root, processed_dir),
        "linux_host_context.json": parse_linux_logs(raw_root, processed_dir),
        "windows_event_context.json": parse_all_windows_logs(raw_root, processed_dir),
        "zeek_session_context.json": parse_all_zeek_logs(raw_root, processed_dir),
    }
    for filename, data in outputs.items():
        with open(os.path.join(processed_dir, filename), "w", encoding="utf-8") as handle:
            json.dump(data or {}, handle, indent=2)
    return outputs


def build_case(scenario: dict, case_root: str = CASES_ROOT) -> dict:
    """Render one scenario into its own raw tree, parse it, build its own DB.

    Each golden case is a self-contained evidence snapshot, so one case's
    telemetry cannot leak into another's verdict.
    """
    import contextlib
    import io

    base = os.path.join(case_root, scenario["id"])
    raw_root = os.path.join(base, "raw")
    processed_dir = os.path.join(base, "processed")
    db_path = os.path.join(base, "triage.db")
    if os.path.isdir(base):
        shutil.rmtree(base)
    os.makedirs(processed_dir, exist_ok=True)

    events = expand(scenario["events"])
    written = render(events, raw_root)
    log = io.StringIO()
    with contextlib.redirect_stdout(log):
        parse_all(raw_root, processed_dir)
    with open(os.path.join(base, "pipeline.log"), "w", encoding="utf-8") as handle:
        handle.write(log.getvalue())
    counts = database.ingest_processed(processed_dir, db_path=db_path, reset=True)
    return {
        "id": scenario["id"],
        "db": db_path,
        "raw_lines": sum(written.values()),
        "tables": counts,
    }


def build(
    scenarios_path: str = SCENARIOS_PATH,
    raw_root: str = RAW_ROOT,
    processed_dir: str = PROCESSED_DIR,
    db_path: str = DB_PATH,
    case_root: str = CASES_ROOT,
) -> dict:
    """Build one database per case, plus a combined database for manual demos."""
    scenarios = load_scenarios(scenarios_path)
    case_summaries = [build_case(scenario, case_root) for scenario in scenarios]

    if os.path.isdir(raw_root):
        shutil.rmtree(raw_root)
    events = [event for scenario in scenarios for event in expand(scenario["events"])]
    render(events, raw_root)
    parse_all(raw_root, processed_dir)
    combined = database.ingest_processed(processed_dir, db_path=db_path, reset=True)

    return {
        "cases": len(scenarios),
        "per_case": case_summaries,
        "combined": {"db": db_path, "tables": combined},
        "raw_lines_combined": len(events),
    }


if __name__ == "__main__":
    summary = build()
    print(
        f"Built {summary['cases']} per-case databases under {CASES_ROOT}/ and a "
        f"combined database at {summary['combined']['db']} "
        f"({summary['raw_lines_combined']} events)."
    )
    for table, rows in summary["combined"]["tables"].items():
        print(f"  {table}: {rows} rows")
    empty = [c["id"] for c in summary["per_case"] if sum(c["tables"].values()) == 0]
    if empty:
        print(f"  cases with no rows (expected for the no-evidence case): {empty}")