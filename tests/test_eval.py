"""Scoring maths: accuracy, false-positive rate, percentiles.

Also covers the v2 grader's absence judge: independent model configuration,
strict fail-closed verdict parsing, and replay grading from the judge
sidecar."""
from __future__ import annotations

import json

import pytest

from agent.client import AssistantMessage, ClientError, StubClient, ToolCall
from config import settings
from eval.run_evals import (
    build_judge_client,
    evaluate_agent_v2,
    judge_absence,
    judge_sidecar_path,
    run_suite_v2,
)
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


# --- Absence judge: independent configuration (no same-model judging) ------


@pytest.fixture()
def ollama_settings(monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "ollama")
    monkeypatch.setattr(settings, "ollama_model", "draw-model-1")
    monkeypatch.setattr(settings, "ollama_base_url", "http://draw-host:11434/v1")
    monkeypatch.setattr(settings, "openai_model", "gpt-draw")
    monkeypatch.setattr(settings, "openai_base_url", "https://draw.example/v1")
    monkeypatch.setattr(settings, "openai_api_key", "sk-draw")
    monkeypatch.setattr(settings, "judge_model", None)
    monkeypatch.setattr(settings, "judge_base_url", None)
    monkeypatch.setattr(settings, "judge_api_key", None)
    return settings


def test_build_judge_client_requires_a_model_in_live_and_record(ollama_settings):
    assert ollama_settings.judge_model is None
    with pytest.raises(ClientError, match="JUDGE_MODEL"):
        build_judge_client(mode="live")
    with pytest.raises(ClientError, match="JUDGE_MODEL"):
        build_judge_client(mode="record")


def test_build_judge_client_must_differ_from_draw_model(ollama_settings):
    ollama_settings.judge_model = "draw-model-1"
    with pytest.raises(ClientError, match="independent"):
        build_judge_client(mode="live")


def test_build_judge_client_is_independently_configured(ollama_settings):
    ollama_settings.judge_model = "judge-model-1"
    client = build_judge_client(mode="live")
    assert client.model == "judge-model-1"
    assert client.temperature == 0.0
    # Defaults: the draw client's endpoint, ollama-style key for ollama.
    assert str(client._client.base_url).rstrip("/") == "http://draw-host:11434/v1"
    assert client._client.api_key == "ollama"
    # Explicit overrides win.
    ollama_settings.judge_base_url = "http://judge-host:8080/v1"
    ollama_settings.judge_api_key = "sk-judge"
    client = build_judge_client(mode="live")
    assert str(client._client.base_url).rstrip("/") == "http://judge-host:8080/v1"
    assert client._client.api_key == "sk-judge"


def test_build_judge_client_openai_provider_defaults(ollama_settings):
    ollama_settings.llm_provider = "openai"
    ollama_settings.judge_model = "judge-model-1"
    client = build_judge_client(mode="live")
    assert client.model == "judge-model-1"
    assert str(client._client.base_url).rstrip("/") == "https://draw.example/v1"
    assert client._client.api_key == "sk-draw"


def test_build_judge_client_replay_needs_no_judge(ollama_settings):
    assert build_judge_client(mode="replay") is None


# --- Absence judging: strict, fail-closed verdict parsing -------------------


@pytest.mark.parametrize(
    ("raw", "verdict"),
    [
        ("OK", "ok"),
        ("violation", "violation"),
        (" VIOLATION ", "violation"),
        ('"OK"', "ok"),
        ("", "nonconforming"),
        (None, "nonconforming"),
        ("The verdict is OK", "nonconforming"),
        ("no violation found", "nonconforming"),
    ],
)
def test_judge_absence_parses_strictly_and_fails_closed(raw, verdict):
    judge = StubClient([AssistantMessage(content=raw)])

    ok, record = judge_absence(judge, "the host was brute forced", ["no compromise claim"])

    assert record["judge_parse"] == verdict
    assert ok is (verdict == "ok")
    assert record["judge_raw"] == (raw or "").strip()


# --- Case pass requires a graded-true absence --------------------------------


def v2_case(case_id="HG-T1", assertions=None):
    return {
        "id": case_id,
        "target": "45.83.220.5",
        "expected_decision": "BLOCK_IP",
        "class": "attack",
        "subclass": "external-bruteforce",
        "assertions": assertions
        or [{"type": "absence", "must_not_claim": ["the host is compromised"]}],
    }


def agent_client():
    """Scripted triage run: one tool call, then a decision."""
    return StubClient(
        [
            AssistantMessage(
                content=None,
                tool_calls=(ToolCall(
                    id="call-1", name="query_triage_db",
                    arguments='{"sql_query":"SELECT * FROM alerts"}'),),
                prompt_tokens=100,
                completion_tokens=20,
            ),
            AssistantMessage(
                content=json.dumps({
                    "decision": "BLOCK_IP",
                    "confidence_score": 90,
                    "reasoning": "Bruteforce from the external host.",
                    "recommended_playbook": "Block at the edge.",
                }),
                prompt_tokens=150,
                completion_tokens=40,
            ),
        ],
        model="draw-model-1",
    )


def run_agent_case(empty_db, monkeypatch, judge, case=None, judge_sidecar=None):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "")
    return evaluate_agent_v2(
        case or v2_case(), empty_db, agent_client(), judge,
        judge_sidecar=judge_sidecar,
    )


def test_case_pass_requires_absence_judged_true(empty_db, monkeypatch):
    judge = StubClient([AssistantMessage(content="OK")])
    result = run_agent_case(empty_db, monkeypatch, judge)

    assert result["absence_ok"] is True
    assert result["case_pass"] is True


def test_case_pass_fails_when_judge_says_violation(empty_db, monkeypatch):
    judge = StubClient([AssistantMessage(content="VIOLATION")])
    result = run_agent_case(empty_db, monkeypatch, judge)

    assert result["absence_ok"] is False
    assert result["case_pass"] is False
    assert result["absence_reasons"]
    assert result["absence_judge"][0]["judge_parse"] == "violation"


def test_case_pass_fails_on_nonconforming_judge_output(empty_db, monkeypatch):
    judge = StubClient([AssistantMessage(content="  ")])
    result = run_agent_case(empty_db, monkeypatch, judge)

    assert result["absence_ok"] is False
    assert result["case_pass"] is False
    assert result["absence_judge"][0]["judge_parse"] == "nonconforming"


def test_case_pass_fails_on_missing_judge_reply(empty_db, monkeypatch):
    judge = StubClient([AssistantMessage(content=None)])
    result = run_agent_case(empty_db, monkeypatch, judge)

    assert result["absence_ok"] is False
    assert result["case_pass"] is False
    assert result["absence_judge"][0]["judge_parse"] == "nonconforming"


# --- Live/record runs record the judge sidecar -------------------------------


def test_live_run_writes_judge_sidecar(empty_db, monkeypatch, tmp_path):
    sidecar = judge_sidecar_path(str(tmp_path / "rec.jsonl"))
    judge = StubClient([AssistantMessage(content="OK")], model="judge-model-1")

    result = run_agent_case(empty_db, monkeypatch, judge, judge_sidecar=sidecar)

    assert result["absence_ok"] is True
    entry = json.loads(open(sidecar, encoding="utf-8").readline())
    assert entry["case_id"] == "HG-T1"
    assert entry["assertion_index"] == 0
    assert entry["must_not_claim"] == ["the host is compromised"]
    assert entry["judge_model"] == "judge-model-1"
    assert entry["raw"] == "OK"
    assert entry["ok"] is True


# --- Replay grades absence from the recorded sidecar -------------------------


def sidecar_entry(case_id="HG-T1", index=0, raw="OK"):
    return {
        "case_id": case_id,
        "assertion_index": index,
        "must_not_claim": ["the host is compromised"],
        "judge_model": "judge-model-1",
        "raw": raw,
        "ok": raw.strip().upper() == "OK",
    }


def write_sidecar(path, entries):
    with open(path, "w", encoding="utf-8") as handle:
        for entry in entries:
            handle.write(json.dumps(entry) + "\n")
    return path


def test_replay_grades_absence_from_sidecar(empty_db, monkeypatch, tmp_path):
    sidecar = write_sidecar(str(tmp_path / "rec-judge.jsonl"), [sidecar_entry()])

    result = run_agent_case(
        empty_db, monkeypatch, judge=None, judge_sidecar=sidecar)

    assert result["absence_ok"] is True
    assert result["case_pass"] is True
    record = result["absence_judge"][0]
    assert record["judge_parse"] == "ok"
    assert record["judge_model"] == "judge-model-1"


def test_replay_fails_when_recorded_verdict_is_violation(
        empty_db, monkeypatch, tmp_path):
    sidecar = write_sidecar(
        str(tmp_path / "rec-judge.jsonl"), [sidecar_entry(raw="VIOLATION")])

    result = run_agent_case(
        empty_db, monkeypatch, judge=None, judge_sidecar=sidecar)

    assert result["absence_ok"] is False
    assert result["case_pass"] is False
    assert result["absence_judge"][0]["judge_parse"] == "violation"
    assert any("recorded" in r for r in result["absence_reasons"])


def test_replay_fails_closed_on_missing_sidecar(empty_db, monkeypatch, tmp_path):
    result = run_agent_case(
        empty_db, monkeypatch, judge=None,
        judge_sidecar=str(tmp_path / "absent-judge.jsonl"))

    assert result["absence_ok"] is False
    assert result["case_pass"] is False
    record = result["absence_judge"][0]
    assert record["judge_parse"] == "missing_sidecar"
    assert "judge sidecar" in " ".join(result["absence_reasons"])


def test_replay_fails_closed_on_missing_sidecar_entry(
        empty_db, monkeypatch, tmp_path):
    # The sidecar exists but records a different case: no verdict for HG-T1.
    sidecar = write_sidecar(
        str(tmp_path / "rec-judge.jsonl"),
        [sidecar_entry(case_id="HG-OTHER", index=0)])

    result = run_agent_case(
        empty_db, monkeypatch, judge=None, judge_sidecar=sidecar)

    assert result["absence_ok"] is False
    assert result["case_pass"] is False
    assert result["absence_judge"][0]["judge_parse"] == "missing_entry"


def test_replay_run_reads_the_replay_path_sidecar(
        empty_db, monkeypatch, tmp_path):
    replay_path = str(tmp_path / "rec.jsonl")
    monkeypatch.setattr(settings, "replay_path", replay_path)
    write_sidecar(judge_sidecar_path(replay_path), [sidecar_entry()])
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "")

    outcome = run_suite_v2(
        mode="replay", client=agent_client(), dataset=[v2_case()],
        db_override=empty_db,
    )

    row = outcome["rows"][0]
    assert row["absence_ok"] is True
    assert row["case_pass"] is True
    assert outcome["judge"] == "judge-model-1"


def test_replay_run_without_a_sidecar_fails_absence(
        empty_db, monkeypatch, tmp_path):
    replay_path = str(tmp_path / "rec.jsonl")
    monkeypatch.setattr(settings, "replay_path", replay_path)
    assert not __import__("os").path.exists(judge_sidecar_path(replay_path))
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "")

    outcome = run_suite_v2(
        mode="replay", client=agent_client(), dataset=[v2_case()],
        db_override=empty_db,
    )

    row = outcome["rows"][0]
    assert row["absence_ok"] is False
    assert row["case_pass"] is False
    assert row["absence_judge"][0]["judge_parse"] == "missing_sidecar"


def test_absence_recall_counts_judge_verdicts_not_cases():
    """summary absence recall is per assertion: cases with no absence
    assertion (absence_ok defaults True) must not inflate the denominator."""
    from eval.run_evals import summarise_v2

    dataset = [
        {"id": "A", "subclass": "fam1", "expected": "IGNORE"},
        {"id": "B", "subclass": "fam1", "expected": "IGNORE"},
        {"id": "C", "subclass": "fam1", "expected": "IGNORE"},
    ]
    rows = [
        {"id": "A", "expected": "IGNORE", "decision": "IGNORE", "case_pass": False,
         "absence_ok": False, "absence_judge": [
             {"ok": True, "judge_parse": "ok"},
             {"ok": False, "judge_parse": "violation"}]},
        {"id": "B", "expected": "IGNORE", "decision": "IGNORE", "case_pass": False,
         "absence_ok": True, "absence_judge": [{"ok": True, "judge_parse": "ok"}]},
        {"id": "C", "expected": "IGNORE", "decision": "IGNORE", "case_pass": True,
         "absence_ok": True, "absence_judge": []},
    ]

    absence = summarise_v2(rows, dataset)["assertion_recall"]["absence"]
    assert absence == {"graded": 3, "met": 2, "recall": 0.667}