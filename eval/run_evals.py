"""Score the triage agent and the rule baseline on the golden dataset.

Two numbers, one table, one run: the LLM agent and the deterministic rules
answer the same cases against the same evidence, and the results file records
the model, the corpus hash and the per-case rows that produced the summary.

    python -m eval.run_evals --mode replay
    python -m eval.run_evals --mode live        # needs a model endpoint
    python -m eval.run_evals --mode record      # live + write the replay file

Replay is the default path for CI and for anyone reading the repo: it needs no
network, no GPU and no API key.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import sys
import time
from datetime import datetime, timezone

import database
from agent.client import LLMClient, build_client, OpenAIClient
from agent.core import run_triage_agent
from agent.rules import classify
from config import settings
from eval.corpus_build import CASES_ROOT, build as build_corpus

GOLDEN_PATH = "eval/golden_dataset.json"
SCENARIOS_PATH = "eval/corpus/scenarios.json"
RESULTS_DIR = "eval/results"

# An eval run stops a triage after this many model turns. A case needing more
# is looping; the run is recorded as a crash rather than allowed to burn the
# whole context window.
EVAL_MAX_TURNS = 12

# v2 (stage-4b real-vendor holdout) dataset: cases carry an `assertions` list
# with a decision assertion plus independent non-decision assertions, and a
# literal SQL-LIKE evidence signature per case. The v1 flat schema above
# (`expected_evidence` + `target_identifier`) is graded exactly as before.
HOLDOUT_PATH = "eval/datasets/real-vendor-holdout.json"
# Payload column that holds the row text for each table (SQL-LIKE target).
V2_PAYLOAD_COLUMN = {
    "endpoint_events": "event_data",
    "network_traffic": "session_data",
    "alerts": "alert_data",
}
V2_MATCH_COLUMN = {
    "network_traffic": {"src_ip": "src_ip", "dest_ip": "dest_ip",
                        "dest_port": "dest_port"},
    "alerts": {"src_ip": "src_ip", "dest_ip": "dest_ip",
               "dest_port": "dest_port"},
    "endpoint_events": {"hostname": "hostname"},
}
ASSERTION_TYPES = ("attribution", "action", "restraint", "absence", "evidence")

# The absence judge is deterministic: temperature 0, a fixed prompt, and its
# raw output recorded in the result artifact (protocol §3.6).
JUDGE_TEMPERATURE = 0.0
JUDGE_SYSTEM = (
    "You are a strict, deterministic fact-checking judge. Compare a triage "
    "verdict against a list of forbidden claims. The verdict violates the "
    "rule if it asserts or implies any forbidden claim. Answer with exactly "
    "one word: VIOLATION or OK. No other text."
)


def is_v2_dataset(dataset: list[dict]) -> bool:
    return bool(dataset) and all("assertions" in case for case in dataset)


def evidence_db_count(a: dict, db_path: str) -> int:
    """Literal SQL-LIKE count: rows in `a['source']` whose payload column
    contains the signature and whose match columns compare equal."""
    table = a["source"]
    payload = V2_PAYLOAD_COLUMN[table]
    sql = f"SELECT COUNT(*) AS n FROM {table} WHERE {payload} LIKE ?"
    params: list[object] = [f"%{a['signature']}%"]
    for key, value in (a.get("match") or {}).items():
        column = V2_MATCH_COLUMN[table].get(key, key)
        sql += f" AND {column} = ?"
        params.append(int(value) if key == "dest_port" else value)
    rows = database.query(sql, tuple(params), db_path=db_path)
    return int(rows[0]["n"]) if rows else 0


def check_static_assertions(case: dict, reasoning: str) -> dict:
    """Deterministic substring checks on the verdict reasoning. The absence
    assertions are left to the temperature-0 judge."""
    checks: dict[str, bool | None] = {}
    low = (reasoning or "").lower()
    for a in case["assertions"]:
        if a["type"] == "attribution":
            ok = all(m.lower() in low for m in a["must_mention"])
            checks["attribution_ok"] = ok and checks.get("attribution_ok", True)
        elif a["type"] == "action":
            ok = (all(v.lower() in low for v in a["verbs"])
                  and all(r.lower() in low for r in a["reference"]))
            checks["action_ok"] = ok and checks.get("action_ok", True)
        elif a["type"] == "restraint":
            ok = not any(f.lower() in low for f in a["forbid"])
            checks["restraint_ok"] = ok and checks.get("restraint_ok", True)
    return checks


def judge_absence(judge_client: LLMClient, reasoning: str,
                  must_not_claim: list[str]) -> tuple[bool, dict]:
    prompt = (
        "Triage verdict under review:\n"
        f"{reasoning}\n\n"
        "Forbidden claims (the verdict must not assert or imply any of "
        "these):\n"
        + "\n".join(f"- {claim}" for claim in must_not_claim)
        + "\n\nDoes the verdict assert or imply any forbidden claim? "
          "Answer with exactly one word: VIOLATION or OK."
    )
    message = judge_client.complete(
        [{"role": "system", "content": JUDGE_SYSTEM},
         {"role": "user", "content": prompt}],
        tools=[],
    )
    raw = (message.content or "").strip()
    ok = "VIOLATION" not in raw.upper()
    return ok, {
        "judge_model": judge_client.model,
        "judge_temperature": JUDGE_TEMPERATURE,
        "judge_prompt": prompt,
        "judge_raw": raw,
        "judge_tokens": message.prompt_tokens + message.completion_tokens,
    }


def evidence_surfaces(case: dict, tool_log: list[dict]) -> tuple[int, int, list[str]]:
    """How many literal evidence signatures appeared in the agent's tool log."""
    blob = "\n".join(entry.get("result", "") for entry in tool_log)
    found = []
    for a in case["assertions"]:
        if a["type"] == "evidence" and a["signature"] in blob:
            found.append(a["signature"])
    total = sum(1 for a in case["assertions"] if a["type"] == "evidence")
    return len(found), total, found


def build_judge_client(mode: str = "live") -> LLMClient | None:
    """Same model/endpoint as the draw client but pinned to temperature 0.
    Judge calls are never recorded: their raw output is stored in the result
    artifact, and the replay gate only replays the triage conversations."""
    if mode == "replay":
        return None
    client = build_client(mode="live")
    if not isinstance(client, OpenAIClient):
        return None
    if settings.llm_provider == "ollama":
        base_url, api_key = settings.ollama_base_url, "ollama"
    else:
        base_url, api_key = settings.openai_base_url, settings.openai_api_key
    return OpenAIClient(
        model=client.model,
        base_url=base_url,
        api_key=api_key,
        temperature=JUDGE_TEMPERATURE,
        seed=client.seed,
        timeout=900.0,
        max_tokens=client.max_tokens,
    )


def evaluate_agent_v2(
    case: dict,
    db_path: str,
    client: LLMClient,
    judge_client: LLMClient | None,
    max_turns: int = EVAL_MAX_TURNS,
    price_in: float = 0.0,
    price_out: float = 0.0,
) -> dict:
    settings.triage_db_path = db_path
    started = time.perf_counter()
    try:
        result = run_triage_agent(
            case["target"],
            client=client,
            max_turns=max_turns,
            alert_text=case_alert_text(db_path, case["target"]),
        )
        latency_ms = (time.perf_counter() - started) * 1000
        cost = (
            result.prompt_tokens / 1_000_000 * price_in
            + result.completion_tokens / 1_000_000 * price_out
        )
        reasoning = result.action.reasoning or ""
        decision = result.action.decision
        checks = check_static_assertions(case, reasoning)
        found, total, signatures = evidence_surfaces(case, result.tool_log)
        absence_records: list[dict] = []
        absence_ok: bool | None = True
        for a in case["assertions"]:
            if a["type"] != "absence":
                continue
            if judge_client is None:
                absence_ok = None
                continue
            ok, record = judge_absence(judge_client, reasoning, a["must_not_claim"])
            absence_records.append({"must_not_claim": a["must_not_claim"], **record})
            absence_ok = absence_ok and ok
        db_counts = {}
        for a in case["assertions"]:
            if a["type"] == "evidence":
                db_counts[a["signature"][:80]] = evidence_db_count(a, db_path)
        row = {
            "decision": decision,
            "confidence": result.action.confidence_score,
            "reasoning": reasoning,
            "playbook": result.action.recommended_playbook,
            "latency_ms": latency_ms,
            "tokens": result.total_tokens,
            "cost_usd": round(cost, 6),
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
            "tool_calls": result.tool_calls,
            "turns": result.turns,
            "decision_ok": decision == case["expected_decision"],
            "checks": checks,
            "absence_ok": absence_ok,
            "absence_judge": absence_records,
            "evidence_found": found,
            "evidence_total": total,
            "evidence_signatures": signatures,
            "evidence_db_counts": db_counts,
            "case_pass": bool(decision == case["expected_decision"])
            and all(checks.values())
            and absence_ok is not False
            and found == total,
            "error": None,
        }
        return row
    except Exception as exc:  # noqa: BLE001 - record, do not crash the suite
        latency_ms = (time.perf_counter() - started) * 1000
        return {
            "decision": None,
            "confidence": None,
            "reasoning": "",
            "latency_ms": latency_ms,
            "tokens": 0,
            "tool_calls": 0,
            "turns": 0,
            "decision_ok": False,
            "checks": {},
            "absence_ok": None,
            "absence_judge": [],
            "evidence_found": 0,
            "evidence_total": sum(
                1 for a in case["assertions"] if a["type"] == "evidence"),
            "evidence_signatures": [],
            "evidence_db_counts": {},
            "case_pass": False,
            "error": f"{type(exc).__name__}: {exc}"[:400],
        }


def evaluate_rules_v2(case: dict, db_path: str) -> dict:
    """Draw 0: deterministic rules baseline against the v2 assertions.
    Absence assertions stay ungraded (no model available for the judge)."""
    base = evaluate_rules(case, db_path)
    reasoning = base.get("reasoning") or ""
    checks = check_static_assertions(case, reasoning)
    db_counts = {}
    for a in case["assertions"]:
        if a["type"] == "evidence":
            db_counts[a["signature"][:80]] = evidence_db_count(a, db_path)
    row = dict(base)
    decision_ok = base["decision"] == case["expected_decision"]
    row.update({
        "decision_ok": decision_ok,
        "checks": checks,
        "absence_ok": None,
        "absence_judge": [],
        "evidence_db_counts": db_counts,
        "case_pass": bool(decision_ok and all(checks.values())),
    })
    return row


def summarise_v2(rows: list[dict], dataset: list[dict]) -> dict:
    total = len(rows)
    decision_ok = sum(1 for r in rows if r.get("decision_ok"))
    case_pass = sum(1 for r in rows if r.get("case_pass"))
    per_type: dict[str, dict[str, float]] = {}
    for a_type in ASSERTION_TYPES:
        key = f"{a_type}_ok"
        if a_type == "absence":
            graded = [r for r in rows if r.get("absence_ok") is not None]
            met = sum(1 for r in graded if r["absence_ok"])
        elif a_type == "evidence":
            graded = [r for r in rows if r.get("evidence_total")]
            met = sum(1 for r in graded
                      if r.get("evidence_found", 0) == r.get("evidence_total"))
        else:
            graded = [r for r in rows if key in r.get("checks", {})]
            met = sum(1 for r in graded if r["checks"].get(key))
        per_type[a_type] = {
            "graded": len(graded),
            "met": met,
            "recall": round(met / len(graded), 3) if graded else None,
        }
    family_acc: dict[str, float] = {}
    subclass_of = {c["id"]: c["subclass"] for c in dataset}
    by_family: dict[str, list[dict]] = {}
    for r in rows:
        by_family.setdefault(subclass_of[r["id"]], []).append(r)
    for fam, fam_rows in by_family.items():
        family_acc[fam] = round(
            sum(1 for r in fam_rows if r.get("case_pass")) / len(fam_rows), 3)
    benign = [r for r in rows if r["expected"] == "IGNORE"]
    fp = [r for r in benign if r.get("decision") not in (None, "IGNORE")]
    return {
        "cases": total,
        "decision_ok": decision_ok,
        "decision_accuracy": round(decision_ok / total, 4) if total else 0.0,
        "case_pass": case_pass,
        "case_pass_rate": round(case_pass / total, 4) if total else 0.0,
        "false_positives": len(fp),
        "false_positive_rate": round(len(fp) / len(benign), 4) if benign else None,
        "assertion_recall": per_type,
        "macro_family_accuracy": round(
            statistics.fmean(family_acc.values()), 4) if family_acc else None,
        "family_accuracy": family_acc,
        "errors": sum(1 for r in rows if r.get("error")),
    }


def case_db(case_id: str, cases_root: str = CASES_ROOT) -> str:
    return os.path.join(cases_root, case_id, "triage.db")


def load_dataset(path: str = GOLDEN_PATH) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def dataset_digest(paths: list[str] | None = None) -> str:
    digest = hashlib.sha256()
    for path in paths or [GOLDEN_PATH, SCENARIOS_PATH]:
        with open(path, "rb") as handle:
            digest.update(handle.read())
    return digest.hexdigest()[:16]


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


def ensure_corpus(cases_root: str = CASES_ROOT) -> None:
    dataset = load_dataset()
    missing = [case["id"] for case in dataset if not os.path.exists(case_db(case["id"], cases_root))]
    if missing:
        print(f"[corpus] building {len(missing)} missing case database(s)...")
        build_corpus()


def evidence_recall(case: dict, tool_log: list[dict]) -> tuple[int, int]:
    """How many expected evidence signatures the agent actually surfaced."""
    blob = "\n".join(entry.get("result", "") for entry in tool_log)
    found = 0
    for item in case.get("expected_evidence", []):
        if item["signature"] in blob:
            found += 1
    return found, len(case.get("expected_evidence", []))


def case_alert_text(db_path: str, target: str) -> str | None:
    """First alert on record for this target, as an alert queue would show it."""
    try:
        rows = database.query(
            "SELECT alert_data FROM alerts WHERE src_ip = ? OR dest_ip = ? LIMIT 3",
            (target, target),
            db_path=db_path,
        )
    except FileNotFoundError:
        return None
    messages = []
    for row in rows:
        try:
            payload = json.loads(row["alert_data"])
        except (TypeError, json.JSONDecodeError):
            continue
        if payload.get("message"):
            messages.append(f"{payload.get('sig_id', 'ALERT')}: {payload['message']}")
    return " | ".join(messages) if messages else None


def evaluate_rules(case: dict, db_path: str) -> dict:
    started = time.perf_counter()
    target = case.get("target_identifier") or case.get("target")
    verdict = classify(target or "", db_path=db_path)
    latency_ms = (time.perf_counter() - started) * 1000
    return {
        "decision": verdict.decision,
        "confidence": verdict.confidence_score,
        "reasoning": verdict.reasoning,
        "score": verdict.score,
        "latency_ms": latency_ms,
        "tokens": 0,
        "tool_calls": 0,
        "turns": 0,
        "evidence_found": None,
        "evidence_total": len(case.get("expected_evidence", [])),
        "error": None,
    }


def evaluate_agent(
    case: dict,
    db_path: str,
    client: LLMClient,
    max_turns: int = EVAL_MAX_TURNS,
    price_in: float = 0.0,
    price_out: float = 0.0,
) -> dict:
    settings.triage_db_path = db_path
    started = time.perf_counter()
    try:
        result = run_triage_agent(
            case["target_identifier"],
            client=client,
            max_turns=max_turns,
            alert_text=case_alert_text(db_path, case["target_identifier"]),
        )
        latency_ms = (time.perf_counter() - started) * 1000
        found, total = evidence_recall(case, result.tool_log)
        cost = (
            result.prompt_tokens / 1_000_000 * price_in
            + result.completion_tokens / 1_000_000 * price_out
        )
        return {
            "decision": result.action.decision,
            "confidence": result.action.confidence_score,
            "reasoning": result.action.reasoning,
            "playbook": result.action.recommended_playbook,
            "latency_ms": latency_ms,
            "tokens": result.total_tokens,
            "cost_usd": round(cost, 6),
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
            "tool_calls": result.tool_calls,
            "turns": result.turns,
            "evidence_found": found,
            "evidence_total": total,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001 - record, do not crash the suite
        latency_ms = (time.perf_counter() - started) * 1000
        return {
            "decision": None,
            "confidence": None,
            "reasoning": "",
            "latency_ms": latency_ms,
            "tokens": 0,
            "tool_calls": 0,
            "turns": 0,
            "evidence_found": 0,
            "evidence_total": len(case.get("expected_evidence", [])),
            "error": f"{type(exc).__name__}: {exc}"[:400],
        }


def summarise(rows: list[dict], dataset: list[dict] | list) -> dict:
    total = len(rows)
    correct = sum(1 for row in rows if row["decision"] == row["expected"])
    benign = [row for row in rows if row["expected"] == "IGNORE"]
    malicious = [row for row in rows if row["expected"] != "IGNORE"]
    false_positives = [row for row in benign if row["decision"] not in (None, "IGNORE")]
    missed = [row for row in malicious if row["decision"] in (None, "IGNORE")]
    latencies = [row["latency_ms"] for row in rows if row["error"] is None]
    tokens = [row["tokens"] for row in rows if row["error"] is None]
    evidence = [
        (row["evidence_found"], row["evidence_total"])
        for row in rows
        if row["evidence_found"] is not None and row["evidence_total"]
    ]
    evidence_ratio = (
        sum(found for found, _ in evidence) / sum(total_ for _, total_ in evidence)
        if evidence else None
    )
    costs = [row.get("cost_usd") or 0.0 for row in rows if row["error"] is None]
    cost_total = sum(costs)

    return {
        "cases": total,
        "correct": correct,
        "accuracy": correct / total if total else 0.0,
        "benign_cases": len(benign),
        "false_positives": len(false_positives),
        "false_positive_rate": len(false_positives) / len(benign) if benign else None,
        "malicious_cases": len(malicious),
        "missed": len(missed),
        "miss_rate": len(missed) / len(malicious) if malicious else None,
        "errors": sum(1 for row in rows if row["error"]),
        "latency_p50_ms": statistic_round(percentile(latencies, 0.50)),
        "latency_p95_ms": statistic_round(percentile(latencies, 0.95)),
        "mean_tokens_per_alert": round(statistics.fmean(tokens), 1) if tokens else 0.0,
        "evidence_recall": round(evidence_ratio, 3) if evidence_ratio is not None else None,
        "cost_usd_total": round(cost_total, 4),
        "cost_usd_per_1000_alerts": round(cost_total / total * 1000, 2) if total else 0.0,
        "cases_in_dataset": len(dataset),
    }


def statistic_round(value: float) -> float:
    return round(value, 1)


def format_table(rules: dict, agent: dict | None) -> str:
    if agent is None:
        agent = {
            "correct": 0, "cases": 0, "accuracy": None, "false_positive_rate": None,
            "false_positives": 0, "benign_cases": 0, "missed": 0, "malicious_cases": 0,
            "latency_p50_ms": None, "latency_p95_ms": None, "mean_tokens_per_alert": None,
            "evidence_recall": None, "errors": "-",
        }

    def line(label, rule_value, agent_value):
        return f"  {label:<26}{rule_value:>14}{agent_value:>16}"

    def pct(value):
        return "n/a" if value is None else f"{value * 100:.1f}%"

    def num(value, suffix=""):
        return "n/a" if value is None else f"{value}{suffix}"

    rows = [
        line("Decision accuracy", f"{rules['correct']}/{rules['cases']}", f"{agent['correct']}/{agent['cases']}"),
        line("Accuracy", pct(rules["accuracy"]), pct(agent["accuracy"])),
        line("False-positive rate", pct(rules["false_positive_rate"]), pct(agent["false_positive_rate"])),
        line("False positives", f"{rules['false_positives']}/{rules['benign_cases']}", f"{agent['false_positives']}/{agent['benign_cases']}"),
        line("Missed detections", f"{rules['missed']}/{rules['malicious_cases']}", f"{agent['missed']}/{agent['malicious_cases']}"),
        line("Latency p50", num(rules["latency_p50_ms"], " ms"), num(agent["latency_p50_ms"], " ms")),
        line("Latency p95", num(rules["latency_p95_ms"], " ms"), num(agent["latency_p95_ms"], " ms")),
        line("Mean tokens / alert", num(round(rules["mean_tokens_per_alert"], 1) if rules["mean_tokens_per_alert"] else None, ""), num(round(agent["mean_tokens_per_alert"], 1) if agent["mean_tokens_per_alert"] else None, "")),
        line("Evidence recall", pct(rules["evidence_recall"]), pct(agent["evidence_recall"])),
        line("Crashed runs", str(rules["errors"]), str(agent["errors"])),
        line("Cost (run)", f"${rules.get('cost_usd_total', 0):.4f}", f"${agent.get('cost_usd_total', 0):.4f}"),
        line("Cost / 1,000 alerts", f"${rules.get('cost_usd_per_1000_alerts', 0):.2f}", f"${agent.get('cost_usd_per_1000_alerts', 0):.2f}"),
    ]
    header = f"  {'metric':<26}{'rules':>14}{'agent':>16}"
    return "\n".join([header, "  " + "-" * 54] + rows)


def run_suite(
    mode: str,
    client: LLMClient | None,
    dataset: list[dict],
    db_override: str | None,
    max_turns: int = EVAL_MAX_TURNS,
    cases_root: str = CASES_ROOT,
    price_in: float = 0.0,
    price_out: float = 0.0,
) -> dict:
    rules_rows: list[dict] = []
    agent_rows: list[dict] = []

    for case in dataset:
        db_path = db_override or case_db(case["id"], cases_root=cases_root)
        rule_result = evaluate_rules(case, db_path)
        rules_rows.append({"id": case["id"], "expected": case["expected_decision"], **rule_result})

        if client is not None:
            agent_result = evaluate_agent(
                case, db_path, client, max_turns=max_turns,
                price_in=price_in, price_out=price_out,
            )
            agent_rows.append({"id": case["id"], "expected": case["expected_decision"], **agent_result})
            mark = "ok " if agent_result["decision"] == case["expected_decision"] else "MISS"
            print(
                f"  [{mark}] {case['id']:<32} expected={case['expected_decision']:<12} "
                f"agent={agent_result['decision'] or 'ERROR':<12} "
                f"({agent_result['latency_ms'] / 1000:.1f}s, {agent_result['tool_calls']} tools, "
                f"{agent_result['tokens']} tok)"
            )

    rules_summary = summarise(rules_rows, dataset)
    agent_summary = summarise(agent_rows, dataset) if agent_rows else None
    return {
        "mode": mode,
        "rules": {"summary": rules_summary, "rows": rules_rows},
        "agent": {"summary": agent_summary, "rows": agent_rows} if agent_rows else None,
    }


def run_suite_v2(
    mode: str,
    client: LLMClient | None,
    dataset: list[dict],
    db_override: str | None,
    max_turns: int = EVAL_MAX_TURNS,
    price_in: float = 0.0,
    price_out: float = 0.0,
) -> dict:
    """Stage-4b holdout suite: one row per case graded against its full
    assertion list (decision first, then attribution/action/restraint/absence/
    evidence)."""
    judge_client = build_judge_client(mode=mode) if client is not None else None
    rows: list[dict] = []
    for case in dataset:
        db_path = db_override or case_db(case["id"])
        if client is None:
            result = evaluate_rules_v2(case, db_path)
        else:
            result = evaluate_agent_v2(case, db_path, client, judge_client,
                                       max_turns=max_turns, price_in=price_in,
                                       price_out=price_out)
        rows.append({
            "id": case["id"],
            "expected": case["expected_decision"],
            "target": case["target"],
            "class": case["class"],
            "subclass": case["subclass"],
            **result,
        })
        checks = result.get("checks", {})
        print(
            f"  [{'ok ' if result['decision_ok'] else 'MISS'}] {case['id']:<8} "
            f"expected={case['expected_decision']:<12} "
            f"got={result['decision'] or 'ERROR':<12} "
            f"checks={sum(1 for v in checks.values() if v)}/{len(checks)} "
            f"absence={result['absence_ok']} "
            f"evidence={result['evidence_found']}/{result['evidence_total']}"
            + (f" err={result['error']}" if result.get("error") else "")
        )
    return {
        "mode": mode,
        "summary": summarise_v2(rows, dataset),
        "rows": rows,
        "judge": (rows[0]["absence_judge"][0]["judge_model"]
                  if rows and rows[0].get("absence_judge") else None),
    }


def write_v2_result(args, dataset, client, model, label) -> int:
    """Run a stage-4b holdout draw and persist the result artifact with the
    pinned draw metadata (protocol: never report a best-draw headline without
    per-draw scores and sampling metadata)."""
    db_path = args.db
    if db_path is None:
        print("v2 holdout requires --db (the combined real-vendor database)",
              file=sys.stderr)
        return 2
    outcome = run_suite_v2(
        args.mode, client, dataset, db_path,
        max_turns=args.max_turns,
        price_in=args.price_in,
        price_out=args.price_out,
    )
    summary = outcome["summary"]
    judge_model = outcome["judge"]
    pinned = {
        "model": model,
        "temperature": getattr(client, "temperature", None),
        "seed": getattr(client, "seed", None),
        "max_tokens": getattr(client, "max_tokens", None),
        "max_turns": args.max_turns,
        "judge_model": judge_model,
        "judge_temperature": JUDGE_TEMPERATURE if judge_model else None,
        "db": db_path,
    }
    print(
        f"\n[v2] decision accuracy {summary['decision_accuracy']} "
        f"({summary['decision_ok']}/{summary['cases']}) | case pass "
        f"{summary['case_pass_rate']} ({summary['case_pass']}/{summary['cases']}) "
        f"| FP {summary['false_positives']} | macro family "
        f"{summary['macro_family_accuracy']}\n"
    )

    os.makedirs(RESULTS_DIR, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "mode": args.mode,
        "model": model,
        "dataset": args.dataset,
        "dataset_sha256": dataset_digest([args.dataset]),
        "schema": "v2-assertions",
        "pinned": pinned,
        "price_in_per_mtok": args.price_in,
        "price_out_per_mtok": args.price_out,
        "recorded_at": stamp,
        "host": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "summary": summary,
        "per_case": [
            {k: v for k, v in row.items() if k != "reasoning"}
            for row in outcome["rows"]
        ],
        "reasoning_by_case": {row["id"]: row["reasoning"]
                              for row in outcome["rows"]},
    }
    json_path = os.path.join(RESULTS_DIR, f"{label}.json")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    text_path = os.path.join(RESULTS_DIR, f"{label}.txt")
    with open(text_path, "w", encoding="utf-8") as handle:
        handle.write(
            f"mode={args.mode} model={model} cases={len(dataset)} "
            f"dataset={dataset_digest([args.dataset])} at {stamp}\n"
            f"decision_accuracy={summary['decision_accuracy']} "
            f"case_pass={summary['case_pass_rate']} "
            f"fp={summary['false_positives']} "
            f"macro_family={summary['macro_family_accuracy']}\n"
        )
    print(f"wrote {json_path} and {text_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score the triage agent on the golden set.")
    parser.add_argument("--mode", default="replay", choices=["replay", "live", "record"])
    parser.add_argument("--label", default=None, help="results file stem (default: mode + model)")
    parser.add_argument("--rules-only", action="store_true", help="skip the model entirely")
    parser.add_argument("--db", default=None, help="evaluate every case against one combined database")
    parser.add_argument("--max-turns", type=int, default=EVAL_MAX_TURNS,
                        help="max model turns per case before the run is recorded as a crash")
    parser.add_argument("--no-build", action="store_true", help="use existing case databases")
    parser.add_argument("--dataset", default=GOLDEN_PATH, help="case list to score")
    parser.add_argument("--cases-dir", default=CASES_ROOT, help="directory holding <case>/triage.db")
    parser.add_argument("--split", default=None, choices=["dev", "holdout"],
                        help="score only the cases marked with this split")
    parser.add_argument("--price-in", type=float, default=0.0,
                        help="USD per 1M input tokens, for the cost column")
    parser.add_argument("--price-out", type=float, default=0.0,
                        help="USD per 1M output tokens, for the cost column")
    args = parser.parse_args(argv)

    digest_paths = [args.dataset]
    if args.dataset == GOLDEN_PATH:
        digest_paths.append(SCENARIOS_PATH)

    dataset = load_dataset(args.dataset)
    if args.split:
        dataset = [case for case in dataset if case.get("split") in (None, args.split)]
        if not dataset:
            print(f"no cases marked {args.split!r} in {args.dataset}", file=sys.stderr)
            return 2

    if not args.no_build and args.dataset == GOLDEN_PATH:
        ensure_corpus(args.cases_dir)

    client = None
    model = "rules-only"
    if not args.rules_only:
        client = build_client(mode=args.mode)
        model = client.model

    print(f"[eval] mode={args.mode} model={model} cases={len(dataset)} "
          f"split={args.split or 'all'} dataset={dataset_digest(digest_paths)}")

    if is_v2_dataset(dataset):
        label = args.label or (model.replace("/", "-").replace(":", "-")
                               if client else "rules-only")
        return write_v2_result(args, dataset, client, model, label)

    outcome = run_suite(
        args.mode, client, dataset, args.db,
        max_turns=args.max_turns,
        cases_root=args.cases_dir,
        price_in=args.price_in,
        price_out=args.price_out,
    )

    table = format_table(
        outcome["rules"]["summary"],
        outcome["agent"]["summary"] if outcome["agent"] else None,
    )
    print("\n" + table + "\n")

    label = args.label or (model.replace("/", "-").replace(":", "-") if client else "rules-only")
    os.makedirs(RESULTS_DIR, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "mode": args.mode,
        "model": model,
        "max_turns": args.max_turns,
        "dataset": args.dataset,
        "split": args.split,
        "price_in_per_mtok": args.price_in,
        "price_out_per_mtok": args.price_out,
        "recorded_at": stamp,
        "dataset_sha256": dataset_digest(digest_paths),
        "host": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "summary": table,
        "rules": outcome["rules"]["summary"],
        "agent": outcome["agent"]["summary"] if outcome["agent"] else None,
        "per_case": [
            {k: v for k, v in row.items() if k != "reasoning"}
            for row in (outcome["agent"]["rows"] if outcome["agent"] else outcome["rules"]["rows"])
        ],
        "rule_rows": [{k: v for k, v in row.items() if k != "reasoning"} for row in outcome["rules"]["rows"]],
    }
    json_path = os.path.join(RESULTS_DIR, f"{label}.json")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    text_path = os.path.join(RESULTS_DIR, f"{label}.txt")
    with open(text_path, "w", encoding="utf-8") as handle:
        handle.write(f"mode={args.mode} model={model} cases={len(dataset)} "
                     f"split={args.split or 'all'} dataset={dataset_digest(digest_paths)} at {stamp}\n\n{table}\n")
    print(f"wrote {json_path} and {text_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())