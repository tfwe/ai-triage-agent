import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from pydantic import BaseModel, Field
from typing import Literal

from agent.client import AssistantMessage, LLMClient, build_client
from agent.tools import check_ip_reputation, query_triage_db

MAX_TURNS = 25

SYSTEM_PROMPT = """You are an autonomous Tier 2 SOC Analyst triage agent. You investigate alerts using the `query_triage_db` tool.

DATABASE SCHEMA:
1. `alerts` (id INTEGER, timestamp TEXT, sensor TEXT, src_ip TEXT, dest_ip TEXT, alert_data JSON)
2. `network_traffic` (uid TEXT, timestamp REAL, src_ip TEXT, dest_ip TEXT, dest_port INTEGER, protocol TEXT, session_data JSON)
3. `endpoint_events` (id INTEGER, timestamp TEXT, hostname TEXT, source TEXT, event_data JSON)
4. `firewall_events` (id INTEGER, timestamp TEXT, hostname TEXT, message_id TEXT, message TEXT)
*Note: This is static historical data. Never filter using relative time (e.g., datetime('now')).

INVESTIGATION & SQL RULES:
- Query all four tables for the target identifier. Check both indexed columns (e.g., src_ip, hostname) AND JSON payload columns (LIKE '%target%').
- Schema strictness: NEVER search for string hostnames in `src_ip` or `dest_ip` columns. IP columns strictly contain IP addresses. Queries like `src_ip = 'WEB-BO-01'` are invalid and strictly forbidden.
- Ban on manual limits: DO NOT use `LIMIT` in your queries. The database tool automatically restricts output to 15 rows. 
- Chronological sorting: You MUST append `ORDER BY timestamp DESC` to your queries so you see the most recent activity first.
- Output limits: If the tool warns you that the output was truncated, you must tighten your `WHERE` clauses (e.g., filter by specific destination ports, protocols, or exact IPs).
- Adapt on failure: If a query returns an error or 0 rows, do not repeat the exact same query. Adjust your logic.

DECISION FRAMEWORK:
- ISOLATE_HOST: Malicious activity occurring ON an internal host (compromised credentials, lateral movement, malware, beaconing outbound). 
- BLOCK_IP: External IP is the primary threat vector with no confirmed host compromise (inbound scanning, external C2 receiving beacons).
- IGNORE: Benign activity (mistyped password, known-good IP) or zero matching evidence after an exhaustive search across all tables.

FLOW-ONLY EVIDENCE (no alerts, no endpoint events, only network_traffic):
Judge the shape of the flows, not the volume alone.
- Many flows from the target across many destination ports, short durations, small payloads: scanning -> BLOCK_IP.
- Many flows from the target to one service port (21, 22, 23, 25, 80, 443, 445, 3389) with tiny or empty responses: brute force -> BLOCK_IP.
- Hundreds of near-identical small flows: decide by role. If the target sources them it is attacking; if it receives them it is a victim, and the correct action on the victim is IGNORE.
- A steady stream of equal-size flows to one peer: beaconing. The internal host sending them is compromised (ISOLATE_HOST); the external peer receiving them is C2 (BLOCK_IP).
- Ordinary service use (DNS, NTP, HTTP to varied peers, mixed payload sizes, long sessions) is IGNORE even when the flow count is high.

CRITICAL EXECUTION:
1. Execute `query_triage_db` FIRST. 
2. Never include your final decision inside a tool call argument.
3. When your investigation is complete, output ONLY a raw JSON object matching this schema exactly:
{
  "decision": "BLOCK_IP" | "ISOLATE_HOST" | "IGNORE",
  "confidence_score": <integer 1-100>,
  "reasoning": "<string detailing the evidence>",
  "recommended_playbook": "<string>"
}"""

TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "check_ip_reputation",
            "description": "Check if an IP address is malicious.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip_address": {
                        "type": "string",
                        "description": "The IP address to check",
                    }
                },
                "required": ["ip_address"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_triage_db",
            "description": (
                "Query the local SQLite database containing host telemetry. Use "
                "standard SQL. The database has four tables: endpoint_events, "
                "network_traffic, alerts, and firewall_events."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "sql_query": {
                        "type": "string",
                        "description": "The exact SQL SELECT query to execute.",
                    }
                },
                "required": ["sql_query"],
            },
        },
    },
]


class TriageAction(BaseModel):
    decision: Literal["BLOCK_IP", "ISOLATE_HOST", "IGNORE"]
    confidence_score: int = Field(ge=1, le=100)
    reasoning: str
    recommended_playbook: str


@dataclass
class TriageResult:
    """A decision plus the operational numbers an eval needs."""

    action: TriageAction
    turns: int = 0
    tool_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    tool_log: list[dict[str, Any]] = field(default_factory=list)

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class AgentLoopError(RuntimeError):
    """Raised when the agent never produces a valid decision."""


def _execute_tool(name: str, arguments: str) -> str:
    try:
        args = json.loads(arguments)
    except json.JSONDecodeError:
        args = {}

    if name == "check_ip_reputation":
        ip = args.get("ip_address")
        if not ip:
            return (
                "ERROR: Missing 'ip_address' argument. DO NOT include your final "
                "decision or reasoning in tool arguments. Only pass the requested IP."
            )
        return check_ip_reputation(ip)

    if name == "query_triage_db":
        sql_query = args.get("sql_query")
        if not sql_query:
            return (
                "ERROR: Missing 'sql_query' argument. DO NOT output your final JSON "
                "decision here. Only output the SQL query."
            )
        return query_triage_db(sql_query)

    return f"ERROR: unknown tool '{name}'. Available tools: check_ip_reputation, query_triage_db."


def run_triage_agent(
    target_identifier: str,
    client: Optional[LLMClient] = None,
    max_turns: int = MAX_TURNS,
    verbose: bool = False,
    alert_text: Optional[str] = None,
) -> TriageResult:
    """Investigate one target and return the decision plus usage counters.

    ``alert_text`` carries the signature that fired, the way an alert queue
    would hand it over. The agent still has to verify it against the evidence.
    """
    if client is None:
        client = build_client()

    opening = (
        f"A new alert just dropped for target '{target_identifier}'."
        + (f" The alert reads: {alert_text}" if alert_text else "")
        + " Use query_triage_db to find relevant records in alerts, "
        "endpoint_events, network_traffic or firewall_events, then decide."
    )

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": opening},
    ]

    result = TriageResult(action=TriageAction(
        decision="IGNORE",
        confidence_score=1,
        reasoning="uninitialised",
        recommended_playbook="none",
    ))

    for turn in range(max_turns):
        result.turns = turn + 1
        response: AssistantMessage = client.complete(messages, TOOLS)
        result.prompt_tokens += response.prompt_tokens
        result.completion_tokens += response.completion_tokens

        if response.tool_calls:
            messages.append(response.to_message())
            for call in response.tool_calls:
                result.tool_calls += 1
                if verbose:
                    print(f"\n  [TOOL EXECUTION] {call.name}")
                    print(f"  [ARGS] {call.arguments}\n")
                tool_result = _execute_tool(call.name, call.arguments)
                result.tool_log.append(
                    {"name": call.name, "arguments": call.arguments, "result": tool_result}
                )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": tool_result,
                    }
                )
            continue

        raw_output = (response.content or "").strip()

        match = re.search(r"\{.*\}", raw_output, re.DOTALL)
        if match:
            try:
                result.action = TriageAction.model_validate_json(match.group(0))
                return result
            except Exception:
                pass

        # The model stopped calling tools without producing a valid decision.
        messages.append(response.to_message())
        messages.append(
            {
                "role": "user",
                "content": (
                    "SYSTEM ERROR: You stopped using tools but did not output the "
                    "valid final JSON schema. If your query failed, call the tool "
                    "again with a different SQL statement. If you are done "
                    "investigating, output ONLY the valid JSON schema. No "
                    "conversational text."
                ),
            }
        )

    raise AgentLoopError(
        f"agent did not reach a decision for {target_identifier!r} in {max_turns} turns"
    )


def triage(target_identifier: str, **kwargs) -> TriageAction:
    """Convenience wrapper returning just the decision."""
    return run_triage_agent(target_identifier, **kwargs).action


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Triage one host or IP.")
    parser.add_argument("target", help="hostname or IP address to investigate")
    parser.add_argument(
        "--mode",
        default=None,
        choices=["live", "record", "replay"],
        help="override LLM_MODE from config",
    )
    args = parser.parse_args(argv)

    client = build_client(mode=args.mode)
    result = run_triage_agent(args.target, client=client, verbose=True)
    print("\n--- FINAL AGENT DECISION ---")
    print(result.action.model_dump_json(indent=4))
    print(
        f"turns={result.turns} tool_calls={result.tool_calls} "
        f"tokens={result.total_tokens}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())