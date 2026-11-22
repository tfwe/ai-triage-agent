"""LLM transport for the triage agent.

The agent loop never talks to the OpenAI SDK directly. It talks to an
``LLMClient``, which has three implementations:

* :class:`OpenAIClient`  - a real model, local (Ollama / LM Studio) or hosted.
* :class:`RecordingClient` - wraps another client and appends every
  request/response pair to a JSONL file, so a live run can be replayed later.
* :class:`ReplayClient`  - answers from that JSONL file with no network at all.
* :class:`StubClient`    - scripted answers for unit tests.

Every response is normalised into :class:`AssistantMessage`, so replay, stub
and live runs all drive the same code path in ``agent/core.py``.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Protocol, Sequence


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: str


@dataclass(frozen=True)
class AssistantMessage:
    content: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()
    prompt_tokens: int = 0
    completion_tokens: int = 0

    def to_message(self) -> dict[str, Any]:
        """Convert back to the wire shape the OpenAI API expects."""
        message: dict[str, Any] = {"role": "assistant", "content": self.content}
        if self.tool_calls:
            message["tool_calls"] = [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {"name": call.name, "arguments": call.arguments},
                }
                for call in self.tool_calls
            ]
        return message


class ClientError(RuntimeError):
    """Raised when a client cannot produce a response."""


class ReplayMiss(ClientError):
    """Raised when a replay file has no recorded response for a request."""


def request_key(model: str, messages: Sequence[dict], tools: Sequence[dict]) -> str:
    """Stable hash of a request, used to look up recorded responses.

    Sampling parameters are deliberately excluded: temperature and seed are
    fixed in config, and including them would make recordings brittle to
    cosmetic config edits.
    """
    payload = json.dumps(
        {"model": model, "messages": list(messages), "tools": list(tools)},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class LLMClient(Protocol):
    model: str

    def complete(
        self, messages: Sequence[dict], tools: Sequence[dict]
    ) -> AssistantMessage: ...


class OpenAIClient:
    """Any OpenAI-compatible endpoint: Ollama, LM Studio, or hosted OpenAI."""

    def __init__(
        self,
        model: str,
        base_url: str | None = None,
        api_key: str | None = None,
        temperature: float = 0.1,
        seed: int = 7,
        timeout: float = 180.0,
    ) -> None:
        from openai import OpenAI

        self.model = model
        self.temperature = temperature
        self.seed = seed
        kwargs: dict[str, Any] = {"timeout": timeout}
        if base_url:
            kwargs["base_url"] = base_url.rstrip("/")
        if api_key:
            kwargs["api_key"] = api_key
        kwargs["api_key"] = kwargs.get("api_key") or "not-required"
        self._client = OpenAI(**kwargs)

    def complete(
        self, messages: Sequence[dict], tools: Sequence[dict]
    ) -> AssistantMessage:
        request: dict[str, Any] = {
            "model": self.model,
            "messages": list(messages),
            "tools": list(tools),
            "temperature": self.temperature,
            "seed": self.seed,
        }
        try:
            response = self._client.chat.completions.create(**request)
        except Exception as exc:  # surface provider errors to the caller
            raise ClientError(f"model request failed: {exc}") from exc

        choice = response.choices[0].message
        calls = tuple(
            ToolCall(
                id=call.id,
                name=call.function.name,
                arguments=call.function.arguments or "{}",
            )
            for call in (choice.tool_calls or ())
        )
        usage = getattr(response, "usage", None)
        return AssistantMessage(
            content=choice.content,
            tool_calls=calls,
            prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
        )


class RecordingClient:
    """Delegates to another client and records every exchange to JSONL."""

    def __init__(self, inner: LLMClient, path: str) -> None:
        self.inner = inner
        self.model = inner.model
        self.path = path
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        if not os.path.exists(path):
            open(path, "w").close()

    def complete(
        self, messages: Sequence[dict], tools: Sequence[dict]
    ) -> AssistantMessage:
        response = self.inner.complete(messages, tools)
        record = {
            "key": request_key(self.model, messages, tools),
            "model": self.model,
            "messages": list(messages),
            "tools": list(tools),
            "response": {
                "content": response.content,
                "tool_calls": [
                    {"id": c.id, "name": c.name, "arguments": c.arguments}
                    for c in response.tool_calls
                ],
                "prompt_tokens": response.prompt_tokens,
                "completion_tokens": response.completion_tokens,
            },
        }
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
        return response


class ReplayClient:
    """Answers from a JSONL recording. No network, no model, no GPU."""

    def __init__(self, path: str) -> None:
        if not os.path.exists(path):
            raise ClientError(f"replay file not found: {path}")
        self.path = path
        self.records: dict[str, dict] = {}
        self.model = ""
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                self.records[record["key"]] = record
                self.model = record.get("model", self.model)
        if not self.records:
            raise ClientError(f"replay file is empty: {path}")

    def complete(
        self, messages: Sequence[dict], tools: Sequence[dict]
    ) -> AssistantMessage:
        key = request_key(self.model, messages, tools)
        record = self.records.get(key)
        if record is None:
            raise ReplayMiss(
                f"no recorded response for this request in {self.path}. "
                "Re-record with `python -m eval.record_live` after changing the "
                "prompt, tools, database contents or model."
            )
        payload = record["response"]
        return AssistantMessage(
            content=payload.get("content"),
            tool_calls=tuple(
                ToolCall(id=c["id"], name=c["name"], arguments=c["arguments"])
                for c in payload.get("tool_calls", [])
            ),
            prompt_tokens=payload.get("prompt_tokens", 0),
            completion_tokens=payload.get("completion_tokens", 0),
        )


class StubClient:
    """Scripted responses for tests. Records the requests it received."""

    def __init__(self, responses: Sequence[AssistantMessage], model: str = "stub") -> None:
        self._responses = list(responses)
        self.model = model
        self.requests: list[tuple[list[dict], list[dict]]] = []

    def complete(
        self, messages: Sequence[dict], tools: Sequence[dict]
    ) -> AssistantMessage:
        self.requests.append((list(messages), list(tools)))
        if not self._responses:
            raise ClientError("StubClient ran out of scripted responses")
        return self._responses.pop(0)


def _settings():
    from config import settings

    return settings


def build_client(
    mode: str | None = None,
    replay_path: str | None = None,
    record_path: str | None = None,
) -> LLMClient:
    """Build the client selected by config (``LLM_MODE``, ``LLM_PROVIDER``)."""
    settings = _settings()
    mode = mode or getattr(settings, "llm_mode", "live")

    if mode == "replay":
        path = replay_path or settings.replay_path
        return ReplayClient(path)
    if mode not in ("live", "record"):
        raise ClientError(f"unknown LLM mode: {mode!r}")

    if settings.llm_provider == "ollama":
        inner: LLMClient = OpenAIClient(
            model=settings.ollama_model,
            base_url=settings.ollama_base_url,
            api_key="ollama",
        )
    else:
        if not settings.openai_api_key:
            raise ClientError(
                "OPENAI_API_KEY is missing from the environment but LLM_PROVIDER=openai."
            )
        inner = OpenAIClient(
            model=settings.openai_model,
            api_key=settings.openai_api_key,
            base_url=settings.openai_base_url,
        )
    if mode == "record":
        return RecordingClient(inner, record_path or settings.record_path)
    return inner