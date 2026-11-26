#!/usr/bin/env python3
"""Adversarial contract check for the ai-triage-agent harness (stdlib only).

Five sections, one SECTION line each, exit 1 if any section FAILs:

  1. DATA INVARIANTS   golden set ids unique; public.json dev/holdout split
                       non-empty and disjoint; every decision label legal;
                       eval/corpus/scenarios.json covers every golden case.
  2. TOY END-TO-END    corpus_build is already done by the caller; this runs
                       eval/run_evals.py in --mode replay as a subprocess over
                       the synthetic golden set, with the network blocked and
                       no API key in the environment, and checks its output.
  3. RESULT CORROBORATION
                       parses the README metric tables and compares every
                       reproducible cell against the committed result JSONs.
                       Latency rows are excluded (wall-clock, see README).
  4. SELF-ALIVENESS    the toy run scored > 0 cases and the corpus build
                       produced > 0 case databases.
  5. HOLDOUT REPLAY    replays the committed ornith-r3 holdout recording
                       (eval/recordings/public-ornith-r3-holdout.jsonl) through
                       eval.run_evals against the 14 holdout case databases
                       committed under data/public/cases, with the network
                       blocked. Asserts zero mismatches against
                       eval/results/public-holdout-ornith-r3.json: per-case
                       decision and token count, and agent summary counts
                       (cases, correct, false_positives, missed,
                       mean_tokens_per_alert, evidence_recall). Latency fields
                       are excluded.

Nothing is written to the harness tree. The toy run and the holdout replay
happen in temp copies, which are removed at the end.

Schema facts this script relies on (verified against the repo):
  * Decision labels: agent/core.py TriageAction.decision is
    Literal["BLOCK_IP", "ISOLATE_HOST", "IGNORE"].
  * eval/golden_dataset.json: list of 31 dicts with keys id, target_identifier,
    expected_decision, description, expected_evidence. It has NO split field.
  * eval/datasets/public.json: list of 28 dicts with a split field,
    14 dev and 14 holdout. The dev/holdout check therefore runs on that file.
  * eval/results/*.json: keys rules, agent (each with cases, correct,
    false_positives, benign_cases, missed, malicious_cases, errors,
    mean_tokens_per_alert, evidence_recall, cost_usd_per_1000_alerts,
    false_positive_rate, accuracy, plus latency fields that are excluded),
    and per_case / rule_rows.

Replay offline: run_evals --mode replay calls ReplayClient(REPLAY_PATH), which
only reads a JSONL file. Replay needs no key. The guard below blocks sockets
for the whole subprocess, so a stray network call fails the run instead of
going unnoticed.

Chance floor for section 2: the rules accuracy must be >= the majority-class
share of the golden labels (IGNORE, 12/31 = 0.387). That share is above the
uniform 3-way chance of 1/3, so it is the stricter floor. A rule system below
it is worse than always answering IGNORE. The ceiling is 1.0 by definition,
and the README says the rules were tuned on this corpus, so 31/31 sits at the
ceiling. Section 2 therefore cannot catch a drop that stays above the floor.
Section 3 pins the README value (31/31) and catches it.

Why section 3 corroborates instead of re-executes the public tables: the
CICIDS2017 and NF-UNSW-NB15 source archives are not redistributable and are
not available in CI. Their case databases cannot be rebuilt, so the public
numbers can only be checked against the committed result JSONs. The one
exception is the ornith-r3 holdout run: its 14 case databases are committed,
so section 5 re-executes that recording instead.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter

LEGAL = ("BLOCK_IP", "ISOLATE_HOST", "IGNORE")
GOLDEN = "eval/golden_dataset.json"
SCENARIOS = "eval/corpus/scenarios.json"
PUBLIC = "eval/datasets/public.json"
README = "README.md"
REPLAY_RECORDING = "eval/recordings/agent.jsonl"
TOY_LABEL = "adversarial-toy"
# README "Measured results" caption: dataset digest of the synthetic set.
README_SYNTH_DIGEST = "2a6921379ee5370b"
EXPECTED_SYNTH_CASES = 31

# README synthetic table (header: Metric | Rules | Agent). Source: agent.json
# for both columns, as the README caption says (agent.txt and rules-baseline.txt
# report the same counts).
SYNTH_HEADER = ("Metric", "Rules", "Agent")
SYNTH_COLUMNS = {
    "Rules": ("eval/results/agent.json", "rules"),
    "Agent": ("eval/results/agent.json", "agent"),
}

# README holdout table (header: Metric | Rules | Local 35B | DeepSeek | GPT-6-Luna).
HOLD_HEADER = ("Metric", "Rules", "Local 35B", "DeepSeek V4.1-Flash", "GPT-6-Luna")
HOLD_COLUMNS = {
    "Rules": ("eval/results/public-rules-holdout.json", "rules"),
    "Local 35B": ("eval/results/public-holdout-ornith-final.json", "agent"),
    "DeepSeek V4.1-Flash": ("eval/results/public-holdout-deepseek.json", "agent"),
    "GPT-6-Luna": ("eval/results/public-holdout-gpt6luna.json", "agent"),
}

# Rules-only and holdout result files that must agree on the rules side.
RULES_CROSSCHECK = [
    ("eval/results/rules-baseline.json", "rules"),
    ("eval/results/public-rules-dev.json", "rules"),
]

LATENCY_NOTE = "latency rows excluded (wall-clock of original runs, not reproducible; README)"


def load(path: str):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def sanitized_env() -> dict:
    """Environment for offline replay: no model keys, no LLM routing, no proxy."""
    drop = ("OPENAI_", "OLLAMA_", "LLM_", "REPLAY_", "RECORD_", "ABUSEIPDB_", "TRIAGE_DB_")
    env = {k: v for k, v in os.environ.items() if not k.startswith(drop)}
    env.pop("PYTHONPATH", None)
    env.update({
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "LLM_MODE": "replay",
        "REPLAY_PATH": REPLAY_RECORDING,
    })
    return env


# Runs eval.run_evals with sockets blocked. Any network attempt raises.
GUARD = r'''
import socket, sys, runpy

def _deny(*_a, **_k):
    raise RuntimeError("network access attempted during offline replay")

socket.socket.connect = _deny
socket.socket.connect_ex = _deny
socket.create_connection = _deny
socket.getaddrinfo = _deny
sys.argv = ["eval.run_evals"] + sys.argv[1:]
runpy.run_module("eval.run_evals", run_name="__main__", alter_sys=True)
'''


# ---------------------------------------------------------------- section 1
def section_data(h: str) -> tuple[list[str], list[str]]:
    problems: list[str] = []
    notes: list[str] = []

    golden = load(os.path.join(h, GOLDEN))
    ids = [c.get("id") for c in golden]
    dupes = sorted(i for i, n in Counter(ids).items() if n > 1)
    if not ids:
        problems.append("golden set is empty")
    if dupes:
        problems.append(f"duplicate golden case ids: {dupes}")
    notes.append(f"golden: {len(ids)} cases, {len(set(ids))} unique ids")

    bad = [(c.get("id"), c.get("expected_decision")) for c in golden
           if c.get("expected_decision") not in LEGAL]
    if bad:
        problems.append(f"illegal golden decision labels: {bad[:5]}")
    notes.append(f"golden decision counts: {dict(Counter(c.get('expected_decision') for c in golden))}")

    public = load(os.path.join(h, PUBLIC))
    splits = Counter(c.get("split") for c in public)
    if set(splits) != {"dev", "holdout"}:
        problems.append(f"public.json split values must be exactly dev/holdout, got {dict(splits)}")
    dev = {c["id"] for c in public if c.get("split") == "dev"}
    hold = {c["id"] for c in public if c.get("split") == "holdout"}
    if not dev:
        problems.append("dev split is empty")
    if not hold:
        problems.append("holdout split is empty")
    if dev & hold:
        problems.append(f"dev/holdout overlap: {sorted(dev & hold)[:5]}")
    pids = [c.get("id") for c in public]
    if len(pids) != len(set(pids)):
        problems.append("duplicate public.json case ids")
    pbad = [c.get("id") for c in public if c.get("expected_decision") not in LEGAL]
    if pbad:
        problems.append(f"illegal public.json decision labels: {pbad[:5]}")
    notes.append(f"public.json split: dev={len(dev)} holdout={len(hold)} disjoint={not (dev & hold)}")

    scen = load(os.path.join(h, SCENARIOS))
    scen_ids = [s.get("id") for s in scen]
    if len(scen_ids) != len(set(scen_ids)):
        problems.append("duplicate scenario ids")
    by_id = {s["id"]: s for s in scen}
    missing = [i for i in ids if i not in by_id]
    if missing:
        problems.append(f"scenarios.json does not cover golden cases: {missing[:5]}")
    for case in golden:
        s = by_id.get(case.get("id"))
        if s is None:
            continue
        if s.get("target") != case.get("target_identifier"):
            problems.append(f"{case['id']}: scenario target {s.get('target')} != golden {case.get('target_identifier')}")
        has_events = bool(s.get("events"))
        has_evidence = bool(case.get("expected_evidence"))
        if has_events != has_evidence:
            problems.append(f"{case['id']}: events={has_events} but expected_evidence={has_evidence}")
    notes.append(f"scenarios.json covers {len(ids) - len(missing)}/{len(ids)} golden cases")
    return problems, notes


# ---------------------------------------------------------------- section 2
def section_toy(h: str, tmp: str) -> tuple[list[str], list[str], dict]:
    """Copy the harness (no data/, no .git), rebuild the corpus, replay the golden set."""
    problems: list[str] = []
    notes: list[str] = []
    work = os.path.join(tmp, "harness")
    harness_abs = os.path.abspath(h)

    def ignore(directory, names):
        skip = {n for n in names if n == "__pycache__" or n.endswith(".pyc")
                or (n.startswith("public-") and n.endswith(".jsonl"))}
        if os.path.abspath(directory) == harness_abs:
            skip |= {".git", ".venv", "venv", "data", ".env", ".pytest_cache"}
        return skip

    shutil.copytree(harness_abs, work, ignore=ignore)
    env = sanitized_env()

    build = subprocess.run([sys.executable, "-m", "eval.corpus_build"], cwd=work, env=env,
                           capture_output=True, text=True, timeout=180)
    if build.returncode != 0:
        problems.append(f"corpus_build exit {build.returncode}: {build.stderr.strip()[-300:]}")
        return problems, notes, {}
    cases_root = os.path.join(work, "data", "cases")
    case_dbs = [d for d in os.listdir(cases_root)
                if os.path.exists(os.path.join(cases_root, d, "triage.db"))] if os.path.isdir(cases_root) else []

    # Prove the guard fires: a direct connect through it must raise.
    probe = subprocess.run(
        [sys.executable, "-c", GUARD.split("sys.argv")[0] + "\ntry:\n    socket.create_connection(('127.0.0.1', 9), timeout=1)\n    print('CONNECTED')\nexcept RuntimeError as e:\n    print('BLOCKED', e)\n"],
        cwd=work, env=env, capture_output=True, text=True, timeout=30)
    if "BLOCKED" not in probe.stdout:
        problems.append(f"network guard did not block a connect: {probe.stdout!r} {probe.stderr[-200:]!r}")
    else:
        notes.append("network guard self-test: connect blocked")

    argv = ["--mode", "replay", "--dataset", GOLDEN, "--cases-dir", cases_root,
            "--no-build", "--label", TOY_LABEL]
    started = time.monotonic()
    run = subprocess.run([sys.executable, "-c", GUARD, *argv], cwd=work, env=env,
                         capture_output=True, text=True, timeout=300)
    elapsed = time.monotonic() - started
    notes.append(f"run_evals replay subprocess: exit {run.returncode} in {elapsed:.1f}s")
    if run.returncode != 0:
        problems.append(f"run_evals exit {run.returncode}: {(run.stderr or run.stdout)[-400:]}")
        return problems, notes, {"case_dbs": len(case_dbs)}

    if "network access attempted" in run.stdout + run.stderr:
        problems.append("network access attempted during replay")

    stdout_cases = len(re.findall(r"^\s+\[(?:ok |MISS|FP |ERR)\s*\]", run.stdout, re.MULTILINE))
    m = re.search(r"dataset=([0-9a-f]+)", run.stdout)
    digest = m.group(1) if m else None
    if digest != README_SYNTH_DIGEST:
        problems.append(f"dataset digest {digest} != README {README_SYNTH_DIGEST}")
    else:
        notes.append(f"dataset digest matches README ({README_SYNTH_DIGEST})")

    out_path = os.path.join(work, "eval", "results", f"{TOY_LABEL}.json")
    if not os.path.exists(out_path):
        problems.append("run_evals did not write its results JSON")
        return problems, notes, {"case_dbs": len(case_dbs)}
    try:
        result = load(out_path)
    except json.JSONDecodeError as exc:
        problems.append(f"results JSON does not parse: {exc}")
        return problems, notes, {"case_dbs": len(case_dbs)}

    rows = result.get("rule_rows") or []
    agent_rows = result.get("per_case") or []
    rules = result.get("rules") or {}
    golden = load(os.path.join(work, GOLDEN))
    golden_ids = {c["id"] for c in golden}

    for name, rs in (("rule_rows", rows), ("per_case", agent_rows)):
        if not rs:
            problems.append(f"{name} is empty")
            continue
        bad = [(r.get("id"), r.get("decision")) for r in rs if r.get("decision") not in LEGAL]
        if bad:
            problems.append(f"{name}: illegal decisions {bad[:5]}")
        unknown = [r.get("id") for r in rs if r.get("id") not in golden_ids]
        if unknown:
            problems.append(f"{name}: case ids not in golden set {unknown[:5]}")

    if rules.get("cases") != EXPECTED_SYNTH_CASES:
        problems.append(f"rules scored {rules.get('cases')} cases, expected {EXPECTED_SYNTH_CASES}")
    acc = rules.get("accuracy")
    floor = max(Counter(c["expected_decision"] for c in golden).values()) / len(golden)
    if acc is None or not (floor <= acc <= 1.0):
        problems.append(f"rules accuracy {acc} outside [{floor:.3f} majority-class floor, 1.0 ceiling]")
    # The bound above is loose (the rules were tuned on this corpus, so the
    # ceiling hides regressions). Pin the exact per-case decisions against the
    # committed rules-baseline run as well: the replay must reproduce every one.
    expected_rules = {r["id"]: r["decision"]
                      for r in load(os.path.join(h, "eval/results/rules-baseline.json"))["rule_rows"]}
    got_rules = {r["id"]: r["decision"] for r in rows}
    drift = sorted(i for i in expected_rules if got_rules.get(i) != expected_rules[i])
    if drift or set(got_rules) != set(expected_rules):
        problems.append(f"rules per-case decisions drift from rules-baseline.json: {drift[:5]}")
    else:
        notes.append("rules per-case decisions == eval/results/rules-baseline.json (31/31 ids)")
    notes.append(f"rules accuracy {rules.get('correct')}/{rules.get('cases')} = {acc}; "
                 f"floor {floor:.3f} (majority class IGNORE {12}/31), ceiling 1.0")
    notes.append(f"stdout case lines: {stdout_cases}; agent rows {len(agent_rows)}")
    notes.append("stdout table:\n" + "\n".join("      " + ln for ln in result.get("summary", "").splitlines()))
    return problems, notes, {"case_dbs": len(case_dbs), "scored": len(agent_rows) or len(rows),
                             "stdout_cases": stdout_cases, "result": result}


# ---------------------------------------------------------------- section 3
def readme_tables(text: str) -> list[list[list[str]]]:
    blocks, cur = [], []
    for line in text.splitlines():
        if line.lstrip().startswith("|") and not line.startswith("||"):
            cur.append(line)
        elif cur:
            blocks.append(cur)
            cur = []
    if cur:
        blocks.append(cur)
    tables = []
    for block in blocks:
        rows = [[c.strip() for c in ln.strip().strip("|").split("|")] for ln in block]
        rows = [r for r in rows if not all(re.fullmatch(r":?-+:?", c) for c in r)]
        tables.append(rows)
    return tables


def check_cell(label: str, cell: str, side: dict) -> str | None:
    """Return None when the cell matches the committed JSON, else a reason."""
    lab = label.strip().lower()
    if lab.startswith("latency"):
        return "EXCLUDED"
    if lab == "decision accuracy":
        want_f = [(side["correct"], side["cases"])]
        want_p = [round(100 * side["correct"] / side["cases"], 1)]
        got_f = [(int(a), int(b)) for a, b in re.findall(r"(\d+)/(\d+)", cell)]
        got_p = [float(x) for x in re.findall(r"([\d.]+)%", cell)]
        ok = got_f == want_f and got_p == want_p
        return None if ok else f"want {want_f} {want_p}% got {got_f} {got_p}%"
    if lab == "accuracy":
        # Holdout cells look like "9/14 (64.3%)"; synthetic cells are "100.0%".
        want_p = [round(100 * side["correct"] / side["cases"], 1)]
        got_p = [float(x) for x in re.findall(r"([\d.]+)%", cell)]
        got_f = [(int(a), int(b)) for a, b in re.findall(r"(\d+)/(\d+)", cell)]
        want_f = [(side["correct"], side["cases"])] if got_f else []
        ok = got_p == want_p and got_f == want_f
        return None if ok else f"want {want_f} {want_p}% got {got_f} {got_p}%"
    if lab == "false-positive rate":
        want_f = [(side["false_positives"], side["benign_cases"])]
        want_p = [round(100 * side["false_positives"] / side["benign_cases"], 1)]
        got_f = [(int(a), int(b)) for a, b in re.findall(r"(\d+)/(\d+)", cell)]
        got_p = [float(x) for x in re.findall(r"([\d.]+)%", cell)]
        ok = got_f == want_f and got_p == want_p
        return None if ok else f"want {want_f} {want_p}% got {got_f} {got_p}%"
    if lab == "false positives":
        got = [(int(a), int(b)) for a, b in re.findall(r"(\d+)/(\d+)", cell)]
        want = [(side["false_positives"], side["benign_cases"])]
        return None if got == want else f"want {want} got {got}"
    if lab == "missed detections":
        got = [(int(a), int(b)) for a, b in re.findall(r"(\d+)/(\d+)", cell)]
        want = [(side["missed"], side["malicious_cases"])]
        return None if got == want else f"want {want} got {got}"
    if lab == "mean tokens per alert":
        want = round(side["mean_tokens_per_alert"])
        m = re.fullmatch(r"[\d,]+", cell.strip())
        got = int(cell.replace(",", "")) if m else None
        return None if got == want else f"want {want} got {cell!r}"
    if lab == "evidence recall":
        x = side.get("evidence_recall")
        want = "n/a" if x is None else f"{x * 100:.1f}%"
        return None if cell.strip() == want else f"want {want} got {cell!r}"
    if lab == "crashed runs":
        got = re.fullmatch(r"\d+", cell.strip())
        return None if got and int(cell) == side["errors"] else f"want {side['errors']} got {cell!r}"
    if lab == "cost per 1,000 alerts":
        m = re.search(r"\$([\d.]+)", cell)
        want = side["cost_usd_per_1000_alerts"]
        return None if m and abs(float(m.group(1)) - want) < 0.005 else f"want ${want} got {cell!r}"
    return "UNKNOWN ROW (README row not covered by this check)"


def section_readme(h: str) -> tuple[list[str], list[str]]:
    problems: list[str] = []
    notes: list[str] = []
    text = open(os.path.join(h, README), encoding="utf-8").read()
    tables = readme_tables(text)
    specs = [("synthetic", SYNTH_HEADER, SYNTH_COLUMNS), ("holdout", HOLD_HEADER, HOLD_COLUMNS)]
    for name, header, columns in specs:
        matches = [t for t in tables if t and tuple(t[0]) == header]
        if len(matches) != 1:
            problems.append(f"{name} table: expected one table with header {header}, found {len(matches)}")
            continue
        table = matches[0]
        notes.append(f"{name} table: header {' | '.join(header)}; {len(table) - 1} rows")
        loaded = {col: (load(os.path.join(h, path)), side) for col, (path, side) in columns.items()}
        excluded: list[str] = []
        for row in table[1:]:
            label, cells = row[0], row[1:]
            for col, cell in zip(header[1:], cells):
                payload, side_key = loaded[col]
                side = payload.get(side_key)
                if side is None:
                    problems.append(f"{name}/{col}: no '{side_key}' side in result JSON")
                    continue
                verdict = check_cell(label, cell, side)
                if verdict == "EXCLUDED":
                    excluded.append(label)
                    break
                if verdict is None:
                    notes.append(f"{name} | {label} | {col}: {cell} == {columns[col][0]}[{side_key}]")
                else:
                    problems.append(f"{name} | {label} | {col}: cell {cell!r} -> {verdict} ({columns[col][0]})")
        if excluded:
            notes.append(f"{name}: {LATENCY_NOTE}: {sorted(set(excluded))}")

    # Rules-only runs must agree with the rules side the table is built from.
    base = load(os.path.join(h, "eval/results/agent.json"))["rules"]
    for path, side_key in RULES_CROSSCHECK:
        other = load(os.path.join(h, path))
        if path.endswith("rules-baseline.json"):
            other_side = other.get(side_key)
            keys = ("cases", "correct", "false_positives", "missed", "errors")
            diff = [k for k in keys if other_side.get(k) != base.get(k)]
            if diff:
                problems.append(f"{path} disagrees with agent.json rules side on {diff}")
            else:
                notes.append(f"{path}: rules counts agree with agent.json rules side")
    return problems, notes


# ---------------------------------------------------------------- section 4
def section_alive(toy: dict) -> tuple[list[str], list[str]]:
    problems: list[str] = []
    notes: list[str] = []
    if toy.get("case_dbs", 0) <= 0:
        problems.append(f"corpus build produced {toy.get('case_dbs', 0)} case DBs")
    if toy.get("scored", 0) <= 0:
        problems.append("toy run scored 0 cases")
    if toy.get("stdout_cases", 0) <= 0:
        problems.append("no per-case lines in run_evals stdout")
    notes.append(f"corpus case DBs: {toy.get('case_dbs', 0)}; toy scored: {toy.get('scored', 0)}; "
                 f"stdout case lines: {toy.get('stdout_cases', 0)}")
    return problems, notes


# ---------------------------------------------------------------- section 5
HOLDOUT_RECORDING = "eval/recordings/public-ornith-r3-holdout.jsonl"
HOLDOUT_RESULT = "eval/results/public-holdout-ornith-r3.json"
HOLDOUT_CASES = "data/public/cases"
HOLDOUT_LABEL = "adversarial-holdout-r3"
HOLDOUT_SUMMARY_KEYS = ("cases", "correct", "false_positives", "missed",
                        "mean_tokens_per_alert", "evidence_recall")
HOLDOUT_CASE_KEYS = ("decision", "tokens")  # latency_ms is excluded


def section_holdout(h: str, tmp: str) -> tuple[list[str], list[str]]:
    """Replay the committed ornith-r3 holdout recording and recount against its JSON."""
    problems: list[str] = []
    notes: list[str] = []
    work = os.path.join(tmp, "holdout")
    harness_abs = os.path.abspath(h)
    keep = {os.path.basename(HOLDOUT_RECORDING)}

    def ignore(directory, names):
        skip = {n for n in names if n == "__pycache__" or n.endswith(".pyc")
                or (n.startswith("public-") and n.endswith(".jsonl") and n not in keep)}
        if os.path.abspath(directory) == harness_abs:
            skip |= {".git", ".venv", "venv", "data", ".env", ".pytest_cache"}
        return skip

    shutil.copytree(harness_abs, work, ignore=ignore)
    cases_src = os.path.join(harness_abs, HOLDOUT_CASES)
    cases_dst = os.path.join(work, HOLDOUT_CASES)
    if not os.path.isdir(cases_src):
        problems.append(f"holdout case databases missing: {HOLDOUT_CASES}")
        return problems, notes
    shutil.copytree(cases_src, cases_dst)

    public = load(os.path.join(h, PUBLIC))
    hold_ids = sorted(c["id"] for c in public if c.get("split") == "holdout")
    dbs = [i for i in hold_ids if os.path.exists(os.path.join(cases_dst, i, "triage.db"))]
    if len(dbs) != len(hold_ids):
        problems.append(f"holdout case DBs present {len(dbs)}/{len(hold_ids)}")
        return problems, notes

    # sanitized_env() pins REPLAY_PATH to the golden recording, so override it
    # after the call to point at the r3 holdout recording.
    env = sanitized_env()
    env["REPLAY_PATH"] = HOLDOUT_RECORDING
    argv = ["--mode", "replay", "--dataset", PUBLIC, "--split", "holdout",
            "--cases-dir", cases_dst, "--no-build", "--label", HOLDOUT_LABEL]
    started = time.monotonic()
    run = subprocess.run([sys.executable, "-c", GUARD, *argv], cwd=work, env=env,
                         capture_output=True, text=True, timeout=300)
    notes.append(f"holdout replay subprocess: exit {run.returncode} in {time.monotonic() - started:.1f}s")
    if run.returncode != 0:
        problems.append(f"holdout replay exit {run.returncode}: {(run.stderr or run.stdout)[-400:]}")
        return problems, notes
    if "network access attempted" in run.stdout + run.stderr:
        problems.append("network access attempted during holdout replay")

    out_path = os.path.join(work, "eval", "results", f"{HOLDOUT_LABEL}.json")
    if not os.path.exists(out_path):
        problems.append("holdout replay did not write its results JSON")
        return problems, notes
    got = load(out_path)
    want = load(os.path.join(h, HOLDOUT_RESULT))

    got_cases = {c["id"]: c for c in got.get("per_case") or []}
    want_cases = {c["id"]: c for c in want.get("per_case") or []}
    if set(got_cases) != set(want_cases):
        problems.append(f"holdout case ids differ: missing {sorted(set(want_cases) - set(got_cases))[:5]}, "
                        f"extra {sorted(set(got_cases) - set(want_cases))[:5]}")
    case_mismatch = []
    for cid in sorted(set(got_cases) & set(want_cases)):
        for key in HOLDOUT_CASE_KEYS:
            if got_cases[cid].get(key) != want_cases[cid].get(key):
                case_mismatch.append(f"{cid}.{key}: got {got_cases[cid].get(key)!r} want {want_cases[cid].get(key)!r}")
    if case_mismatch:
        problems.append(f"{len(case_mismatch)} per-case mismatches: {case_mismatch[:5]}")

    got_agent = got.get("agent") or {}
    want_agent = want.get("agent") or {}
    summary_mismatch = [f"{k}: got {got_agent.get(k)!r} want {want_agent.get(k)!r}"
                        for k in HOLDOUT_SUMMARY_KEYS if got_agent.get(k) != want_agent.get(k)]
    if summary_mismatch:
        problems.append(f"agent summary mismatches: {summary_mismatch}")

    if not problems:
        notes.append(f"holdout replay == {HOLDOUT_RESULT}: {len(want_cases)} cases "
                     f"(decision + tokens), agent summary {', '.join(HOLDOUT_SUMMARY_KEYS)}; 0 mismatches")
    notes.append(f"latency fields excluded (wall-clock of the original run; README)")
    return problems, notes


# ---------------------------------------------------------------- driver
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--harness-root", default=".", help="path to the ai-triage-agent checkout")
    args = parser.parse_args(argv)
    h = os.path.abspath(args.harness_root)
    if not os.path.exists(os.path.join(h, GOLDEN)):
        print(f"not a harness root: {h}", file=sys.stderr)
        return 2

    started = time.monotonic()
    tmp = tempfile.mkdtemp(prefix="adv-check-")
    failed = False
    try:
        sections = []
        p1, n1 = section_data(h)
        sections.append(("1 DATA INVARIANTS", p1, n1))

        p2, n2, toy = section_toy(h, tmp)
        sections.append(("2 TOY END-TO-END (offline replay, synthetic golden set)", p2, n2))

        p3, n3 = section_readme(h)
        sections.append(("3 RESULT CORROBORATION (README tables vs result JSON)", p3, n3))

        p4, n4 = section_alive(toy)
        sections.append(("4 SELF-ALIVENESS", p4, n4))

        p5, n5 = section_holdout(h, tmp)
        sections.append(("5 HOLDOUT REPLAY (ornith-r3 recording vs committed result JSON)", p5, n5))

        for title, problems, notes in sections:
            for note in notes:
                print(f"    {note}")
            status = "PASS" if not problems else "FAIL"
            for problem in problems:
                print(f"    ! {problem}")
            print(f"SECTION {title}: {status}")
            failed = failed or bool(problems)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        cleaned = not os.path.exists(tmp)
        print(f"temp dir removed: {cleaned}")
        failed = failed or not cleaned

    elapsed = time.monotonic() - started
    print(f"elapsed: {elapsed:.1f}s (budget 120s)")
    if elapsed > 120:
        print("    ! over the 120s budget")
        failed = True
    print("OVERALL: " + ("FAIL" if failed else "PASS"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
