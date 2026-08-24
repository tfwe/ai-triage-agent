import re
import json
from openai import OpenAI
from pydantic import BaseModel
from typing import Literal
from agent.tools import check_ip_reputation, query_triage_db

from config import settings 

# Configure the client dynamically using the settings object
if settings.llm_provider == "ollama":
    client = OpenAI(
        base_url=settings.ollama_base_url,
        api_key="ollama" 
    )
    TARGET_MODEL = settings.ollama_model
    print(f"🧠 Booting Agent with local Ollama ({TARGET_MODEL})...")
else:
    if not settings.openai_api_key:
        raise ValueError("OPENAI_API_KEY is missing from .env but provider is set to openai.")
        
    client = OpenAI(
        api_key=settings.openai_api_key
    )
    TARGET_MODEL = settings.openai_model
    print(f"☁️ Booting Agent with OpenAI ({TARGET_MODEL})...")

class TriageAction(BaseModel):
    decision: Literal["BLOCK_IP", "ISOLATE_HOST", "IGNORE"]
    confidence_score: int
    reasoning: str
    recommended_playbook: str

def run_triage_agent(target_identifier: str) -> TriageAction:
    # 1. Define the tool schema for the LLM
    tools = [
        {
            "type": "function",
            "function": {
                "name": "check_ip_reputation",
                "description": "Check if an IP address is malicious.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "The IP address to check"}
                    },
                    "required": ["ip_address"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "query_triage_db",
                "description": "Query the local SQLite database containing host telemetry. Use standard SQL. The database has three tables: endpoint_events, network_traffic, and alerts.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "sql_query": {"type": "string", "description": "The exact SQL SELECT query to execute."}
                    },
                    "required": ["sql_query"]
                }
            }
        }
    ]

    # 2. Setup the initial conversation state
    messages = [
        {
            "role": "system", 
            "content": """You are an autonomous Tier 2 SOC Analyst triage agent. You investigate alerts using the `query_triage_db` tool.

DATABASE SCHEMA:
1. `alerts` (id INTEGER, timestamp TEXT, sensor TEXT, src_ip TEXT, dest_ip TEXT, alert_data JSON)
2. `network_traffic` (uid TEXT, timestamp REAL, src_ip TEXT, dest_ip TEXT, dest_port INTEGER, protocol TEXT, session_data JSON)
3. `endpoint_events` (id INTEGER, timestamp TEXT, hostname TEXT, source TEXT, event_data JSON)
*Note: This is static historical data. Never filter using relative time (e.g., datetime('now')).

INVESTIGATION & SQL RULES:
- Query all three tables for the target identifier. Check both indexed columns (e.g., src_ip, hostname) AND JSON payload columns (LIKE '%target%').
- Schema strictness: NEVER search for string hostnames in `src_ip` or `dest_ip` columns. IP columns strictly contain IP addresses. Queries like `src_ip = 'WEB-BO-01'` are invalid and strictly forbidden.
- Ban on manual limits: DO NOT use `LIMIT` in your queries. The database tool automatically restricts output to 50 rows. 
- Chronological sorting: You MUST append `ORDER BY timestamp DESC` to your queries so you see the most recent activity first.
- Output limits: If the tool warns you that the output was truncated, you must tighten your `WHERE` clauses (e.g., filter by specific destination ports, protocols, or exact IPs).
- Adapt on failure: If a query returns an error or 0 rows, do not repeat the exact same query. Adjust your logic.

DECISION FRAMEWORK:
- ISOLATE_HOST: Malicious activity occurring ON an internal host (compromised credentials, lateral movement, malware, beaconing outbound). 
- BLOCK_IP: External IP is the primary threat vector with no confirmed host compromise (inbound scanning, external C2 receiving beacons).
- IGNORE: Benign activity (mistyped password, known-good IP) or zero matching evidence after an exhaustive search across all tables.

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
        },
        {
            "role": "user", 
            "content": f"A new alert just dropped for target '{target_identifier}'. Use query_triage_db to find relevant records in alerts, endpoint_events, or network_traffic." 
        }
    ]


    # 3. The Agent Loop (max 10 iterations to prevent infinite looping)
    for _ in range(25):
        response = client.chat.completions.create(
            model=TARGET_MODEL,
            messages=messages,
            tools=tools,
            temperature=0.1
        )
        message = response.choices[0].message
        
        # If the model wants to call a tool, execute it
        if message.tool_calls:
            messages.append(message) # Append the model's request to call the tool
            
            for tool_call in message.tool_calls:
                print(f"\n  [TOOL EXECUTION] {tool_call.function.name}")
                print(f"  [ARGS] {tool_call.function.arguments}\n")
                
                try:
                    args = json.loads(tool_call.function.arguments)
                except json.JSONDecodeError:
                    args = {}

                if tool_call.function.name == "check_ip_reputation":
                    ip = args.get("ip_address")
                    if not ip:
                        tool_result = "ERROR: Missing 'ip_address' argument. DO NOT include your final decision or reasoning in tool arguments. Only pass the requested IP."
                    else:
                        tool_result = check_ip_reputation(ip)
                        
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": tool_result
                    })
                    
                elif tool_call.function.name == "query_triage_db":
                    query = args.get("sql_query")
                    
                    # If it hallucinates the schema again, smack it with an error
                    if not query:
                        tool_result = "ERROR: Missing 'sql_query' argument. DO NOT output your final JSON decision here. Only output the SQL query."
                    else:
                        from agent.tools import query_triage_db
                        tool_result = query_triage_db(query)
                        
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": tool_result
                    })

            continue # Go back to the top of the loop so the model can read the tool result
        
        # If there are no tool calls, the model should have output our final JSON
        raw_output = message.content.strip()
        
        # 1. Try to extract the JSON block if it included conversational filler
        import re
        match = re.search(r'\{.*\}', raw_output, re.DOTALL)
        
        if match:
            json_candidate = match.group(0)
            try:
                # If it's valid, we're done. Return it and exit the loop.
                return TriageAction.model_validate_json(json_candidate)
            except Exception:
                # If it's a JSON block but fails the schema, let it fall into the trap below
                pass 
                
        # 2. The Yap Trap: The model didn't call a tool and didn't output valid JSON.
        messages.append(message)
        messages.append({
            "role": "user",
            "content": "SYSTEM ERROR: You stopped using tools but did not output the valid final JSON schema. If your query failed, call the tool again with a different SQL statement. If you are done investigating, output ONLY the valid JSON schema. No conversational text."
        })
        
        # Loop continues, forcing the LLM to try again
        continue

    raise Exception("Agent got stuck in a loop and failed to reach a decision.")

if __name__ == "__main__":
    # Load the compressed context we built earlier
    with open("data/processed/host_activity_context.json", "r") as f:
        all_hosts = json.load(f)
    
    # Grab just the first host to test the agent
    first_host_ip = list(all_hosts.keys())[0]
    first_host_data = all_hosts[first_host_ip]
    
    print(f"Running agent on host: {first_host_ip}")
    decision = run_triage_agent(first_host_data)
    
    print("\n--- FINAL AGENT DECISION ---")
    print(decision.model_dump_json(indent=4))
