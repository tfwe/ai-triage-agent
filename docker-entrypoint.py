#!/usr/bin/env python3
"""
Pre-flight check for the AI-triage container.

Imports the app's own `settings` object from config.py (the exact same
object the rest of the app uses), so the provider/URL/model checked here
can never drift out of sync with config.py. If llm_provider is "ollama",
this waits for the Ollama server to become reachable and pulls the
configured model if it isn't already present, then hands off to the
container's real command.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

from config import settings


def wait_for_ollama() -> None:
    if settings.llm_provider != "ollama":
        print(f"[entrypoint] llm_provider={settings.llm_provider!r} -> skipping Ollama check")
        return

    # Ollama's management API (tags/pull) lives at the root, not under /v1
    host = settings.ollama_base_url.rsplit("/v1", 1)[0].rstrip("/")
    model = settings.ollama_model
    timeout_s = int(os.environ.get("OLLAMA_WAIT_TIMEOUT", "60"))

    print(f"[entrypoint] Waiting for Ollama at {host} (model: {model}) ...")
    deadline = time.time() + timeout_s
    tags = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{host}/api/tags", timeout=5) as resp:
                tags = json.load(resp)
                break
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            time.sleep(2)

    if tags is None:
        sys.exit(
            f"[entrypoint] ERROR: couldn't reach Ollama at {host} after {timeout_s}s.\n"
            f"  - Is 'ollama serve' actually running on the host?\n"
            f"  - Is it bound to 0.0.0.0, not just 127.0.0.1? Try starting it with:\n"
            f"      OLLAMA_HOST=0.0.0.0:11434 ollama serve\n"
            f"  - Does docker-compose.yml have extra_hosts: host.docker.internal:host-gateway?"
        )

    names = {m.get("name", "") for m in tags.get("models", [])}
    have_it = model in names or any(n.split(":")[0] == model for n in names)

    if have_it:
        print(f"[entrypoint] Model '{model}' is already pulled - ready.")
        return

    print(f"[entrypoint] Model '{model}' not found locally, pulling ...")
    req = urllib.request.Request(
        f"{host}/api/pull",
        data=json.dumps({"name": model}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=None) as resp:
            for raw_line in resp:
                if not raw_line.strip():
                    continue
                
                data = json.loads(raw_line)
                
                # Catch the silent error in the stream
                if "error" in data:
                    sys.exit(f"[entrypoint] ERROR: Ollama pull failed: {data['error']}")
                    
                status = data.get("status", "")
                if status:
                    print(f"[entrypoint] {status}")
    except urllib.error.URLError as e:
        sys.exit(f"[entrypoint] ERROR: failed to pull '{model}': {e}")

    print(f"[entrypoint] Model '{model}' ready.")


if __name__ == "__main__":
    wait_for_ollama()
    # Hand off to the container's real command, e.g. `python -m eval.run_evals`
    cmd = sys.argv[1:]
    if cmd:
        os.execvp(cmd[0], cmd)

