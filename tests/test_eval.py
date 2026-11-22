"""Scoring maths: accuracy, false-positive rate, percentiles."""
from __future__ import annotations

import pytest

from eval.run_evals import format_table, percentile, summarise


def row(expected, decision, tokens=100, latency_ms=10.0, evidence=(1, 2), error=None):
    return {
        "id": "x",
        "expected": expected,
        "decision": decision,
        "latency_ms": latency_ms,
        "tokens": tokens,
        "evidence_found": evidence[0],
        "evidence_total": evidence[1],
        "error": error,
    }


def test_accuracy_counts_only_exact_decisions():
    rows = [
        row("BLOCK_IP", "BLOCK_IP"),
        row("IGNORE", "ISOLATE_HOST"),
        row("ISOLATE_HOST", None, error="ClientError: boom"),
    ]

    summary = summarise(rows, dataset=rows)

    assert summary["correct"] == 1
    assert summary["cases"] == 3
    assert round(summary["accuracy"], 3) == 0.333
    assert summary["errors"] == 1


def test_false_positive_rate_is_measured_over_benign_cases_only():
    rows = [
        row("IGNORE", "IGNORE"),
        row("IGNORE", "BLOCK_IP"),
        row("BLOCK_IP", "BLOCK_IP"),
        row("BLOCK_IP", "IGNORE"),
    ]

    summary = summarise(rows, dataset=rows)

    assert summary["benign_cases"] == 2
    assert summary["false_positives"] == 1
    assert summary["false_positive_rate"] == 0.5
    assert summary["malicious_cases"] == 2
    assert summary["missed"] == 1
    assert summary["miss_rate"] == 0.5


def test_percentiles_are_nearest_rank():
    values = [1.0, 2.0, 3.0, 4.0, 100.0]

    assert percentile(values, 0.5) == 3.0
    assert percentile(values, 0.95) == 100.0
    assert percentile([], 0.5) == 0.0


def test_evidence_recall_aggregates_over_cases():
    rows = [
        row("BLOCK_IP", "BLOCK_IP", evidence=(2, 2)),
        row("BLOCK_IP", "BLOCK_IP", evidence=(0, 2)),
    ]

    assert summarise(rows, dataset=rows)["evidence_recall"] == 0.5


def test_table_renders_without_an_agent_column():
    table = format_table(summarise([row("IGNORE", "IGNORE")], dataset=[]), None)

    assert "rules" in table
    assert "agent" in table
    assert "n/a" in table