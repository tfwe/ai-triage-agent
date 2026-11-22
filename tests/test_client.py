"""The client layer: request keys, recording, replay, stub."""
from __future__ import annotations

import json

import pytest

from agent.client import (
    AssistantMessage,
    ReplayClient,
    ReplayMiss,
    RecordingClient,
    StubClient,
    ToolCall,
    request_key,
)


def sample_response():
    return AssistantMessage(
        content=None,
        tool_calls=(ToolCall(id="call-1", name="query_triage_db", arguments='{"sql_query":"SELECT 1"}'),),
        prompt_tokens=10,
        completion_tokens=5,
    )


def test_request_key_is_stable_and_order_sensitive():
    messages = [{"role": "user", "content": "hi"}]
    tools = [{"type": "function", "function": {"name": "query_triage_db"}}]

    assert request_key("m", messages, tools) == request_key("m", messages, tools)
    assert request_key("m", messages, tools) != request_key("other", messages, tools)
    assert request_key("m", messages, tools) != request_key("m", messages[::-1] + messages, tools)


def test_record_then_replay_round_trip(tmp_path):
    path = str(tmp_path / "rec.jsonl")
    messages = [{"role": "user", "content": "triage 45.83.220.5"}]
    tools = [{"type": "function", "function": {"name": "query_triage_db"}}]

    recorder = RecordingClient(StubClient([sample_response()], model="stub-1"), path)
    original = recorder.complete(messages, tools)

    replay = ReplayClient(path)
    replayed = replay.complete(messages, tools)

    assert replay.model == "stub-1"
    assert replayed == original
    line = json.loads(open(path, encoding="utf-8").readline())
    assert line["key"] and line["model"] == "stub-1"


def test_replay_miss_raises_rather_than_guessing(tmp_path):
    path = str(tmp_path / "rec.jsonl")
    recorder = RecordingClient(StubClient([sample_response()]), path)
    recorder.complete([{"role": "user", "content": "one"}], [])

    replay = ReplayClient(path)
    with pytest.raises(ReplayMiss):
        replay.complete([{"role": "user", "content": "different question"}], [])


def test_replay_requires_an_existing_file(tmp_path):
    from agent.client import ClientError

    with pytest.raises(ClientError):
        ReplayClient(str(tmp_path / "missing.jsonl"))


def test_stub_client_records_requests():
    client = StubClient([AssistantMessage(content="{}")])
    client.complete([{"role": "user", "content": "x"}], [{"type": "function"}])
    assert client.requests[0][0] == [{"role": "user", "content": "x"}]
    assert client.requests[0][1] == [{"type": "function"}]
    with pytest.raises(Exception):
        client.complete([], [])