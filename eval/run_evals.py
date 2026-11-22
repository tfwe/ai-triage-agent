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
from agent.client import LLMClient, build_client
from agent.core import AgentLoopError, run_triage_agent
from agent.rules import classify
from config import settings
from eval.corpus_build import CASES_ROOT, build as build_corpus

GOLDEN_PATH = "eval/golden_dataset.json"
SCENARIOS_PATH = "eval/corpus/scenarios.json"
RESULTS_DIR = "eval/results"


def case_db(case_id: str, cases_root: str = CASES_ROOT) -> str:
    return os.path.join(cases_root, case_id, "triage.db")


def load_dataset(path: str = GOLDEN_PATH) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def dataset_digest() -> str:
    digest = hashlib.sha256()
    for path in (GOLDEN_PATH, SCENARIOS_PATH):
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


def evaluate_rules(case: dict, db_path: str) -> dict:
    started = time.perf_counter()
    verdict = classify(case["target_identifier"], db_path=db_path)
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


def evaluate_agent(case: dict, db_path: str, client: LLMClient) -> dict:
    settings.triage_db_path = db_path
    started = time.perf_counter()
    try:
        result = run_triage_agent(case["target_identifier"], client=client)
        latency_ms = (time.perf_counter() - started) * 1000
        found, total = evidence_recall(case, result.tool_log)
        return {
            "decision": result.action.decision,
            "confidence": result.action.confidence_score,
            "reasoning": result.action.reasoning,
            "playbook": result.action.recommended_playbook,
            "latency_ms": latency_ms,
            "tokens": result.total_tokens,
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
            "tool_calls": result.tool_calls,
            "turns": result.turns,
            "evidence_found": found,
            "evidence_total": total,
            "error": None,
        }
    except (AgentLoopError, Exception) as exc:  # noqa: BLE001 - record, do not crash the suite
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
    ]
    header = f"  {'metric':<26}{'rules':>14}{'agent':>16}"
    return "\n".join([header, "  " + "-" * 54] + rows)


def run_suite(mode: str, client: LLMClient | None, dataset: list[dict], db_override: str | None) -> dict:
    rules_rows: list[dict] = []
    agent_rows: list[dict] = []

    for case in dataset:
        db_path = db_override or case_db(case["id"])
        rule_result = evaluate_rules(case, db_path)
        rules_rows.append({"id": case["id"], "expected": case["expected_decision"], **rule_result})

        if client is not None:
            agent_result = evaluate_agent(case, db_path, client)
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score the triage agent on the golden set.")
    parser.add_argument("--mode", default="replay", choices=["replay", "live", "record"])
    parser.add_argument("--label", default=None, help="results file stem (default: mode + model)")
    parser.add_argument("--rules-only", action="store_true", help="skip the model entirely")
    parser.add_argument("--db", default=None, help="evaluate every case against one combined database")
    parser.add_argument("--no-build", action="store_true", help="use existing case databases")
    args = parser.parse_args(argv)

    dataset = load_dataset()
    if not args.no_build:
        ensure_corpus()
    else:
        missing = [case["id"] for case in dataset if not os.path.exists(case_db(case["id"]))]
        if missing:
            print(f"missing case databases: {missing}", file=sys.stderr)
            return 2

    client = None
    model = "rules-only"
    if not args.rules_only:
        client = build_client(mode=args.mode)
        model = client.model

    print(f"[eval] mode={args.mode} model={model} cases={len(dataset)} "
          f"dataset={dataset_digest()}")
    outcome = run_suite(args.mode, client, dataset, args.db)

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
        "recorded_at": stamp,
        "dataset_sha256": dataset_digest(),
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
                     f"dataset={dataset_digest()} at {stamp}\n\n{table}\n")
    print(f"wrote {json_path} and {text_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())