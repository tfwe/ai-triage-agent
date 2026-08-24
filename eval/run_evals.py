import json
import time
from pydantic import ValidationError
from agent.core import run_triage_agent, TriageAction

def run_evaluation_suite(dataset_path: str):
    with open(dataset_path, "r") as f:
        cases = json.load(f)

    total_cases = len(cases)
    passed_decision = 0
    valid_schema_count = 0
    latencies = []

    print(f"\n[+] Starting Evaluation Suite: {total_cases} test cases\n" + "=" * 55)

    for case in cases:
        case_id = case["id"]
        expected_decision = case["expected_decision"]
        
        # We no longer pass a giant JSON block. We just pass the target IP or hostname.
        target = case.get("target_identifier")
        
        if not target:
            print(f"[ERROR] {case_id} is missing a 'target_identifier'.")
            continue

        start_time = time.time()
        try:
            # The agent now takes the target and hunts through SQLite on its own
            result = run_triage_agent(target)
            
            latency = time.time() - start_time
            latencies.append(latency)

            # 1. Schema Validation Check
            if isinstance(result, TriageAction):
                valid_schema_count += 1

            # 2. Decision Accuracy Check
            is_match = (result.decision == expected_decision)
            if is_match:
                passed_decision += 1
                status = "PASS"
            else:
                status = f"FAIL (Got {result.decision}, Expected {expected_decision})"

            print(f"[{status}] {case_id} ({latency:.2f}s) -> Decision: {result.decision}")
            print(f"    Reasoning: {result.reasoning}") 
        except ValidationError as ve:
            print(f"[ERROR] {case_id} failed schema validation: {ve}")
        except Exception as e:
            print(f"[ERROR] {case_id} execution error: {e}")

    # Compute Summary Statistics
    accuracy = (passed_decision / total_cases) * 100 if total_cases > 0 else 0
    schema_adherence = (valid_schema_count / total_cases) * 100 if total_cases > 0 else 0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0

    print("=" * 55)
    print(f"EVALUATION SUMMARY:")
    print(f"  * Total Test Cases:      {total_cases}")
    print(f"  * Decision Accuracy:     {accuracy:.1f}%")
    print(f"  * Schema Adherence:      {schema_adherence:.1f}%")
    print(f"  * Mean Latency:          {avg_latency:.2f}s")
    print("=" * 55 + "\n")

if __name__ == "__main__":
    run_evaluation_suite("eval/golden_dataset.json")
