"""The agent loop with a scripted client: no model, no network."""
from __future__ import annotations

import json

import pytest

import database
from agent.client import AssistantMessage, StubClient, ToolCall
from agent.core import AgentLoopError, TriageAction, run_triage_agent
from agent.tools import query_triage_db

DECISION = json.dumps(
    {
        "decision": "BLOCK_IP",
        "confidence_score": 90,
        "reasoning": "Nikto scan against the portal",
        "recommended_playbook": "Block at edge, watch for retries",
    }
)


def tool_message(name, arguments, call_id="call-1"):
    return AssistantMessage(
        content=None,
        tool_calls=(ToolCall(id=call_id, name=name, arguments=arguments),),
        prompt_tokens=100,
        completion_tokens=20,
    )


@pytest.fixture()
def db(empty_db, monkeypatch):
    from config import settings

    settings.triage_db_path = empty_db
    return empty_db


def test_agent_calls_tool_then_returns_decision(db, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "")
    client = StubClient(
        [
            tool_message("query_triage_db", json.dumps({"sql_query": "SELECT * FROM alerts"})),
            AssistantMessage(
                content=DECISION,
                prompt_tokens=150,
                completion_tokens=40,
            ),
        ]
    )

    result = run_triage_agent("45.83.220.5", client=client)

    assert isinstance(result.action, TriageAction)
    assert result.action.decision == "BLOCK_IP"
    assert result.tool_calls == 1
    assert result.turns == 2
    assert result.total_tokens == 310
    # The tool result is fed back to the model before it decides.
    second_request_messages = client.requests[1][0]
    assert any(message.get("role") == "tool" for message in second_request_messages)
    assert client.requests[0][1] == client.requests[1][1]  # same tool schemas


def test_agent_recovers_when_model_answers_without_json(db, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "")
    client = StubClient(
        [
            AssistantMessage(content="I think this is probably fine."),
            tool_message("query_triage_db", json.dumps({"sql_query": "SELECT * FROM alerts"}), "call-2"),
            AssistantMessage(content=f"Here you go:\n{DECISION}"),
        ]
    )

    result = run_triage_agent("45.83.220.5", client=client)

    assert result.action.decision == "BLOCK_IP"
    assert result.turns == 3
    third_request_messages = client.requests[2][0]
    assert any("SYSTEM ERROR" in str(message.get("content")) for message in third_request_messages)


def test_agent_gives_up_after_max_turns(db, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "")
    looping = AssistantMessage(
        content=None,
        tool_calls=(ToolCall(id="c", name="query_triage_db", arguments='{"sql_query":"SELECT 1"}'),),
    )
    client = StubClient([looping] * 5)

    with pytest.raises(AgentLoopError):
        run_triage_agent("WEB-BO-01", client=client, max_turns=3)


def test_agent_handles_bad_tool_arguments(db, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "")
    client = StubClient(
        [
            tool_message("query_triage_db", "not json at all"),
            AssistantMessage(content=DECISION),
        ]
    )

    result = run_triage_agent("45.83.220.5", client=client)

    assert result.tool_log[0]["result"].startswith("ERROR: Missing 'sql_query'")
    assert result.action.decision == "BLOCK_IP"


def test_ip_reputation_without_key_degrades_to_message(db, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "")
    from config import Settings

    settings = Settings(_env_file=None, abuseipdb_api_key=None)
    from agent import tools as tools_module

    monkeypatch.setattr(tools_module, "settings", settings)
    output = tools_module.check_ip_reputation("45.83.220.5")
    assert output.startswith("ERROR: threat-intelligence lookup is unavailable")


def test_query_tool_rejects_hostname_in_ip_column(db, monkeypatch):
    output = query_triage_db("SELECT * FROM alerts WHERE src_ip = 'WEB-BO-01'")
    assert output.startswith("ERROR: Schema violation")


def test_query_tool_caps_rows(db, monkeypatch):
    conn = database.connect(db, readonly=False)
    conn.executemany(
        "INSERT INTO alerts (timestamp, sensor, src_ip, dest_ip, alert_data) VALUES (?, ?, ?, ?, ?)",
        [
            ("05/10-10:00:00.000001", "IDS-BO-EDGE", "45.83.220.5", "10.20.1.10", "{}")
            for _ in range(40)
        ],
    )
    conn.commit()
    conn.close()

    output = query_triage_db("SELECT * FROM alerts WHERE src_ip = '45.83.220.5'")

    assert "truncated" in output
    assert output.count('"timestamp"') == 15