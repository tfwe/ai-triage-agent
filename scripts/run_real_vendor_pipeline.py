#!/usr/bin/env python3
"""Stage the real-vendor corpus, run every parser, ingest, and (optionally)
triage selected targets with the live model.

This is the pass-7 "parsers and agent on real vendor exports" run. It never
touches the synthetic corpus artifacts under ``data/raw`` /
``data/processed``: the corpus in ``data/real-vendor`` is staged into
``data/raw-real`` and everything the parsers and the loader write goes to
``data/processed-real`` (both gitignored).

Outputs ``eval/results/real-vendor-run.json`` with the parser output counts,
quarantine counts, database row counts, and, when agents ran, one entry per
target with the final decision, confidence, reasoning, turns and tokens.

Usage::

    .venv/bin/python scripts/run_real_vendor_pipeline.py \
        --targets <ip-or-host> [<ip-or-host> ...]

    Add --skip-agents for a parser/ingest-only pass.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_REAL = os.path.join(REPO_ROOT, "data", "raw-real")
PROCESSED_REAL = os.path.join(REPO_ROOT, "data", "processed-real")
DB_PATH = os.path.join(PROCESSED_REAL, "real-vendor.db")
CORPUS = os.path.join(REPO_ROOT, "data", "real-vendor")
RESULTS_JSON = os.path.join(REPO_ROOT, "eval", "results", "real-vendor-run.json")
RECORDING = os.path.join(
    REPO_ROOT, "eval", "recordings", "real-vendor-ornith.jsonl"
)

PARSERS = [
    ("asa", "parsers.asa_parser", "parse_asa_logs", "asa_fw_context.json",
     "asa_quarantine.json"),
    ("ecar", "parsers.ecar_parser", "parse_all_ecar_logs",
     "ecar_host_context.json", "ecar_quarantine.json"),
    ("ids", "parsers.ids_parser", "parse_ids_logs", "ids_context.json",
     "ids_quarantine.json"),
    ("linux", "parsers.linux_parser", "parse_linux_logs",
     "linux_host_context.json", None),
    ("windows", "parsers.win_event_parser", "parse_all_windows_logs",
     "windows_event_context.json", None),
    ("zeek", "parsers.zeek_parser", "parse_all_zeek_logs",
     "zeek_session_context.json", "zeek_quarantine.json"),
]


def json_lines(path: str) -> int:
    """Count JSONL rows, or list length when the file is a JSON array."""
    if not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    stripped = text.lstrip()
    if stripped.startswith("["):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            pass
        else:
            return len(data) if isinstance(data, list) else 0
    return sum(1 for line in text.splitlines() if line.strip())


def stage_corpus() -> int:
    """Copy data/real-vendor into the parser-facing data/raw-real tree."""
    if os.path.exists(RAW_REAL):
        shutil.rmtree(RAW_REAL)
    shutil.copytree(CORPUS, RAW_REAL,
                    ignore=shutil.ignore_patterns("*.md", "provenance.json"))
    files = 0
    for _root, _dirs, names in os.walk(RAW_REAL):
        files += len(names)
    return files


def run_parsers() -> dict:
    """Run all parsers and write the returned dicts to the ingest-facing
    output files. The parser entry functions only write their quarantine
    sidecars; the context files are normally written by the __main__ blocks,
    which is why this runner dumps them itself."""
    sys.path.insert(0, REPO_ROOT)
    os.makedirs(PROCESSED_REAL, exist_ok=True)
    results = {}
    for name, module, func, out_name, quarantine_name in PARSERS:
        mod = __import__(module, fromlist=[func])
        entry = getattr(mod, func)
        data = entry(RAW_REAL, PROCESSED_REAL)
        entry_result = {"output": out_name, "keys": 0, "events": 0}
        if isinstance(data, dict):
            entry_result["keys"] = len(data)
            if name == "zeek":
                # Zeek data maps session-key -> session dict; summing
                # count_events() over values would count nested uid lists,
                # not sessions.
                entry_result["events"] = len(data)
            else:
                for value in data.values():
                    entry_result["events"] += count_events(value)
            with open(
                os.path.join(PROCESSED_REAL, out_name), "w", encoding="utf-8"
            ) as fh:
                json.dump(data, fh)
        if quarantine_name:
            entry_result["quarantined"] = json_lines(
                os.path.join(PROCESSED_REAL, quarantine_name)
            )
        results[name] = entry_result
        print(
            f"  {name}: keys={entry_result['keys']} "
            f"events={entry_result['events']} "
            f"quarantined={entry_result.get('quarantined', 'n/a')}"
        )
    return results


def count_events(value) -> int:
    """Count list-wrapped events regardless of the nesting shape."""
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return sum(count_events(v) for v in value.values())
    return 0


def run_ingest() -> dict:
    import database

    counts = database.ingest_processed(
        PROCESSED_REAL, db_path=DB_PATH, reset=True
    )
    return counts


def db_stats() -> dict:
    import sqlite3

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    stats: dict = {}
    stats["endpoint_hosts"] = [
        r[0] for r in cur.execute(
            "SELECT DISTINCT hostname FROM endpoint_events ORDER BY hostname"
        )
    ]
    stats["alert_ips"] = sorted(
        {r[0] for r in cur.execute("SELECT DISTINCT src_ip FROM alerts")}
        | {r[0] for r in cur.execute("SELECT DISTINCT dest_ip FROM alerts")}
    )
    stats["network_ips"] = sorted(
        {r[0] for r in cur.execute("SELECT DISTINCT src_ip FROM network_traffic")}
        | {r[0] for r in cur.execute("SELECT DISTINCT dest_ip FROM network_traffic")}
    )
    conn.close()
    return stats


def run_agent(target: str, mode: str = "record") -> dict:
    env = os.environ.copy()
    # setdefault: caller-provided values win over the runner's defaults.
    for key, value in (
        ("TRIAGE_DB_PATH", DB_PATH),
        ("LLM_PROVIDER", "ollama"),
        ("LLM_MODE", mode),
        ("RECORD_PATH", RECORDING),
        ("REPLAY_PATH", RECORDING),
    ):
        env.setdefault(key, value)
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "agent.core", target, "--mode", mode],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=900,
        )
    except subprocess.TimeoutExpired as exc:
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode(errors="replace")
        return {
            "target": target,
            "exit_code": None,
            "error": "timeout",
            "timeout_seconds": 900,
            "stderr_tail": stderr[-2000:],
        }
    out = proc.stdout
    entry: dict = {"target": target, "exit_code": proc.returncode}
    # raw_decode from the marker: handles nested and single-line JSON,
    # unlike the old '\n'-anchored regex.
    idx = out.rfind("--- FINAL AGENT DECISION ---")
    if idx != -1:
        tail = out[idx + len("--- FINAL AGENT DECISION ---"):].lstrip()
        try:
            decision, _ = json.JSONDecoder().raw_decode(tail)
            entry["decision"] = decision
        except json.JSONDecodeError as exc:
            entry["decision_error"] = f"{exc}: {tail[:200]!r}"
    m = re.search(r"turns=(\d+) tool_calls=(\d+) tokens=(\d+)", out)
    if m:
        entry["turns"] = int(m.group(1))
        entry["tool_calls"] = int(m.group(2))
        entry["tokens"] = int(m.group(3))
    if proc.returncode != 0:
        entry["stderr_tail"] = proc.stderr[-2000:]
    return entry


def main() -> None:
    # Wipe parser output from any previous run so results are never mixed.
    if os.path.exists(PROCESSED_REAL):
        shutil.rmtree(PROCESSED_REAL)
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--targets", nargs="*", default=[])
    ap.add_argument("--skip-agents", action="store_true")
    ap.add_argument("--write-results", action="store_true",
                    help="write eval/results/real-vendor-run.json")
    ap.add_argument("--llm-mode", choices=["live", "record", "replay"], default="record",
                    help="mode passed through to agent.core (record | live | replay)")
    args = ap.parse_args()

    staged = stage_corpus()
    print(f"staged {staged} corpus files into {RAW_REAL}")

    parser_results = run_parsers()
    ingest_counts = run_ingest()
    stats = db_stats()
    print("ingest:", ingest_counts)

    run_doc = {
        "staged_files": staged,
        "parsers": parser_results,
        "ingest_counts": ingest_counts,
        "database": stats,
        "agent_runs": [],
    }

    if not args.skip_agents:
        for target in args.targets:
            print(f"agent run: {target}")
            run_doc["agent_runs"].append(run_agent(target, mode=args.llm_mode))

    if args.write_results:
        os.makedirs(os.path.dirname(RESULTS_JSON), exist_ok=True)
        with open(RESULTS_JSON, "w", encoding="utf-8") as fh:
            json.dump(run_doc, fh, indent=2)
        print(f"wrote {RESULTS_JSON}")
    else:
        print(json.dumps(run_doc, indent=2))


if __name__ == "__main__":
    main()
