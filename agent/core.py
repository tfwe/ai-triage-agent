import json
from openai import OpenAI
from pydantic import BaseModel
from typing import Literal
from agent.tools import check_ip_reputation

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

def run_triage_agent(host_context: dict) -> TriageAction:
    # 1. Define the tool schema for the LLM
    tools = [{
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
    }]

    # 2. Setup the initial conversation state
    messages = [
        {"role": "system", "content": "You are a Tier 2 SOC Analyst. Review host activity, use tools if needed, and output a triage decision."},
        {"role": "user", "content": f"Analyze this host activity:\n{json.dumps(host_context)}"}
    ]

    # 3. The Agent Loop (max 5 iterations to prevent infinite looping)
    for _ in range(5):
        response = client.chat.completions.create(
            model=TARGET_MODEL,
            messages=messages,
            tools=tools,
            # Force the final output to match our Pydantic schema
            response_format={"type": "json_schema", "json_schema": {"name": "triage", "schema": TriageAction.model_json_schema()}}
        )

        message = response.choices[0].message
        
        # If the model wants to call a tool, execute it
        if message.tool_calls:
            messages.append(message) # Append the model's request to call the tool
            
            for tool_call in message.tool_calls:
                if tool_call.function.name == "check_ip_reputation":
                    args = json.loads(tool_call.function.arguments)
                    tool_result = check_ip_reputation(args["ip_address"])
                    
                    # Append the tool's result back to the conversation
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": tool_result
                    })
            continue # Go back to the top of the loop so the model can read the tool result

        # If there are no tool calls, the model has output our final JSON
        return TriageAction.model_validate_json(message.content)

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
