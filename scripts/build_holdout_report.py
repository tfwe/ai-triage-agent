#!/usr/bin/env python3
"""Rebuild eval/results/real-vendor-holdout-report.json programmatically.

Inputs (no hand-typed numbers anywhere):
  eval/results/real-vendor-holdout-ij-r{1,2,3}.json      live draws (independent judge)
  eval/results/real-vendor-holdout-ij-r{1,2,3}-replay.json  replay-gate runs
  eval/results/real-vendor-holdout-draw0.json            rules baseline (--rules-only)

The replay gate asserts, per draw: (a) per-case decisions identical to the
live draw, and (b) per-case absence_ok identical to the live grading (the
judge sidecar replay is deterministic, so a mismatch means the gate is broken).
The gate result is embedded in the report; the builder exits non-zero on any
gate failure.
"""
from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "eval" / "results"
REPORT_PATH = RESULTS / "real-vendor-holdout-report.json"
OLD_REPORT_PATH = RESULTS / "real-vendor-holdout-report.json"

DRAWS = [f"real-vendor-holdout-ij-r{i}" for i in (1, 2, 3)]
REC_TEMPLATE = "eval/recordings/{stem}.jsonl"
SIDECAR_TEMPLATE = "eval/recordings/{stem}.jsonl-judge.jsonl"

METRIC_KEYS = (
    "decision_accuracy",
    "case_pass_rate",
    "macro_family_accuracy",
    "false_positives",
)


def load(path: Path) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def replay_gate(stem: str) -> dict:
    """Compare the replayed run against the live draw (decisions + absence_ok)."""
    live = load(RESULTS / f"{stem}.json")
    replay = load(RESULTS / f"{stem}-replay.json")
    live_rows = {row["id"]: row for row in live["per_case"]}
    replay_rows = {row["id"]: row for row in replay["per_case"]}
    mismatches = []
    for rid, lrow in live_rows.items():
        rrow = replay_rows.get(rid)
        if rrow is None:
            mismatches.append({"id": rid, "field": "case", "reason": "missing in replay"})
            continue
        if lrow["decision"] != rrow["decision"]:
            mismatches.append({
                "id": rid, "field": "decision",
                "live": lrow["decision"], "replay": rrow["decision"],
            })
        if bool(lrow["absence_ok"]) != bool(rrow["absence_ok"]):
            mismatches.append({
                "id": rid, "field": "absence_ok",
                "live": lrow["absence_ok"], "replay": rrow["absence_ok"],
            })
    cases = len(live_rows)
    return {"identical": not mismatches, "mismatches": mismatches, "cases": cases}


def judge_parse_distribution(draws: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for draw in draws:
        for row in draw["per_case"]:
            for entry in row["absence_judge"]:
                verdict = entry["judge_parse"]
                counts[verdict] = counts.get(verdict, 0) + 1
    return counts


def build() -> dict:
    draws = {stem: load(RESULTS / f"{stem}.json") for stem in DRAWS}
    draw0 = load(RESULTS / "real-vendor-holdout-draw0.json")
    old_report = load(OLD_REPORT_PATH)

    # ---- pinned parameters (read straight off the artifacts) ----
    first_pinned = draws[DRAWS[0]]["pinned"]
    for stem, draw in draws.items():
        for key in ("model", "temperature", "seed", "max_tokens", "max_turns",
                    "judge_model", "judge_temperature", "db"):
            if draw["pinned"][key] != first_pinned[key]:
                sys.exit(f"pinned mismatch on {key} in {stem}")
    model = first_pinned["model"]
    if model != draws[DRAWS[1]]["model"] or model != draws[DRAWS[2]]["model"]:
        sys.exit("model mismatch across draws")

    # ---- per-draw metrics + gates ----
    live_draws = []
    gate_failures = []
    for name, stem in zip(("r1", "r2", "r3"), DRAWS):
        draw = draws[stem]
        summary = draw["summary"]
        gate = replay_gate(stem)
        if not gate["identical"]:
            gate_failures.append({"draw": name, **gate})
        live_draws.append({
            "name": name,
            "result_artifact": f"eval/results/{stem}.json",
            "recording": REC_TEMPLATE.format(stem=stem),
            "judge_sidecar": SIDECAR_TEMPLATE.format(stem=stem),
            "replay_gate": gate,
            "pinned": draw["pinned"],
            "recorded_at": draw["recorded_at"],
            "metrics": {
                "decision_accuracy": summary["decision_accuracy"],
                "decision_ok": summary["decision_ok"],
                "cases": summary["cases"],
                "case_pass": summary["case_pass"],
                "case_pass_rate": summary["case_pass_rate"],
                "false_positives": summary["false_positives"],
                "assertion_recall": summary["assertion_recall"],
                "family_accuracy": summary["family_accuracy"],
                "macro_family_accuracy": summary["macro_family_accuracy"],
                "errors": summary["errors"],
            },
        })
    if gate_failures:
        for failure in gate_failures:
            print(f"REPLAY GATE FAILURE: {failure}", file=sys.stderr)
        sys.exit("replay gate failed; not rebuilding the report")

    # ---- aggregate: mean, full min-max range, spread, unanimity ----
    per_draw = [d["metrics"] for d in live_draws]
    aggregate = {
        "mean": {
            key: round(statistics.fmean(m[key] for m in per_draw), 4)
            for key in METRIC_KEYS
        },
        "min": {
            key: min(m[key] for m in per_draw) for key in METRIC_KEYS
        },
        "max": {
            key: max(m[key] for m in per_draw) for key in METRIC_KEYS
        },
        "spread": {
            key: round(
                max(m[key] for m in per_draw) - min(m[key] for m in per_draw), 4
            )
            for key in METRIC_KEYS
        },
    }
    # absence recall (graded by the independent judge) per draw and range
    absence_recall = [m["assertion_recall"]["absence"]["recall"] for m in per_draw]
    aggregate["absence_recall_judged"] = {
        "per_draw": absence_recall,
        "min": min(absence_recall),
        "max": max(absence_recall),
    }

    rows_by_draw = [
        {row["id"]: row for row in draws[stem]["per_case"]} for stem in DRAWS
    ]
    case_ids = list(rows_by_draw[0])
    unanimous_pass = sorted(
        rid for rid in case_ids if all(rows[rid]["case_pass"] for rows in rows_by_draw)
    )
    unanimous_decision = sorted(
        rid for rid in case_ids
        if len({rows[rid]["decision"] for rows in rows_by_draw}) == 1
    )
    aggregate.update({
        "unanimous_pass_all3_cases": len(unanimous_pass),
        "unanimous_pass_all3_rate": round(len(unanimous_pass) / len(case_ids), 3),
        "unanimous_pass_all3_ids": unanimous_pass,
        "unanimous_decision_all3_ids": unanimous_decision,
        "judge_parse_distribution": judge_parse_distribution(list(draws.values())),
        "replay_gates_all_passed": True,
    })

    # ---- draw 0 rules baseline (freshly regenerated by --rules-only) ----
    draw0_summary = draw0["summary"]
    draw0_block = {
        "model": "rules-baseline",
        "db": "data/processed-real/real-vendor.db",
        "dataset_sha256": draw0["dataset_sha256"],
        "metrics": {
            "decision_accuracy": draw0_summary["decision_accuracy"],
            "decision_ok": draw0_summary["decision_ok"],
            "cases": draw0_summary["cases"],
            "case_pass_rate": draw0_summary["case_pass_rate"],
            "case_pass": draw0_summary["case_pass"],
            "false_positives": draw0_summary["false_positives"],
            "assertion_recall": draw0_summary["assertion_recall"],
            "family_accuracy": draw0_summary["family_accuracy"],
            "macro_family_accuracy": draw0_summary["macro_family_accuracy"],
            "errors": draw0_summary["errors"],
        },
        "prediction_check": old_report.get("draw0_rules_baseline", {}).get(
            "prediction_check"),
    }

    # ---- dataset facts ----
    dataset_rows = load(ROOT / "eval" / "datasets" / "real-vendor-holdout.json")
    n_attack = sum(1 for c in dataset_rows if c["class"] == "attack")
    n_benign = len(dataset_rows) - n_attack

    report = {
        "protocol": (
            "consult-2b approved: per-draw scores r1/r2/r3, 3-draw mean, "
            "min-max range + spread, unanimous pass@all3, macro-averaged "
            "family accuracy, replay gate per draw. No best-draw headline. "
            "Absence assertions are graded by an independent judge model with "
            "fail-closed strict parsing; judge verdicts are recorded in a "
            "sidecar and replayed deterministically."
        ),
        "model": model,
        "temperature": first_pinned["temperature"],
        "seed": first_pinned["seed"],
        "max_tokens": first_pinned["max_tokens"],
        "max_turns": first_pinned["max_turns"],
        "judge_model": first_pinned["judge_model"],
        "judge_temperature": first_pinned["judge_temperature"],
        "db": first_pinned["db"],
        "params_provenance": (
            "temperature/seed/max_tokens are the draw client's OpenAIClient "
            "configuration (agent/client.py: defaults temperature=0.1, "
            "seed=7, max_tokens=5500), sent as fields on every wire request. "
            "The recordings and .reqlog files store request keys, messages "
            "and responses but NOT sampling parameters, so these values "
            "cannot be cross-checked from the logs alone. The judge runs at "
            "temperature 0.0 with fail-closed strict verdict parsing."
        ),
        "dataset": (
            f"eval/datasets/real-vendor-holdout.json ({len(dataset_rows)} "
            f"cases: {n_attack} attack / {n_benign} benign)"
        ),
        "grader_revision": (
            "Independent judge model (not the draw client), fail-closed "
            "strict parsing of the judge verdict (empty/nonconforming output "
            "grades as nonconforming, never as a pass), and replayable judge "
            "verdict sidecars. This grader change invalidates all pre-redraw "
            "draws, which have been removed; the numbers here are not "
            "comparable to them."
        ),
        "draw0_rules_baseline": draw0_block,
        "live_draws": live_draws,
        "aggregate": aggregate,
        "disclosures": old_report["disclosures"],
    }
    return report


def main() -> int:
    report = build()
    with open(REPORT_PATH, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=1)
        handle.write("\n")
    print(f"wrote {REPORT_PATH}")
    print(f"mean: {report['aggregate']['mean']}")
    print(f"min:  {report['aggregate']['min']}")
    print(f"max:  {report['aggregate']['max']}")
    print(f"unanimous pass@all3: {report['aggregate']['unanimous_pass_all3_cases']} "
          f"{report['aggregate']['unanimous_pass_all3_ids']}")
    print(f"judge_parse distribution: "
          f"{report['aggregate']['judge_parse_distribution']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
