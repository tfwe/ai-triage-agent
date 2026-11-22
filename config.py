from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Literal, Optional

class Settings(BaseSettings):
    # Core Toggle
    llm_provider: Literal["openai", "ollama"] = "ollama"

    # How the agent gets its answers: "live" hits a real model, "record" hits a
    # real model and writes JSONL, "replay" answers from that JSONL with no
    # network. Evals default to replay so results are reproducible.
    llm_mode: Literal["live", "record", "replay"] = "live"
    replay_path: str = "eval/recordings/agent.jsonl"
    record_path: str = "eval/recordings/agent.jsonl"

    # OpenAI Config
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-5.6-luna"

    abuseipdb_api_key: Optional[str] = None

    # Ollama Config (also valid for LM Studio: it speaks the same /v1 API)
    ollama_base_url: str = "http://localhost:11434/v1"
    ollama_model: str = "devstral-small-2:24b"

    # Triage database used by the query_triage_db tool
    triage_db_path: str = "data/processed/triage.db"

    # Automatically load from the .env file in the root directory
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

# Instantiate it once here so the rest of the app can just import this object
settings = Settings()