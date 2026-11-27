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
    openai_base_url: Optional[str] = None
    openai_model: str = "gpt-5.6-luna"

    abuseipdb_api_key: Optional[str] = None

    # Ollama Config (also valid for LM Studio: it speaks the same /v1 API)
    ollama_base_url: str = "http://localhost:11434/v1"
    ollama_model: str = "devstral-small-2:24b"

    # Triage database used by the query_triage_db tool
    triage_db_path: str = "data/processed/triage.db"

    # Absence judge (v2 grader). Must be an INDEPENDENT model from the draw
    # client: temperature 0 pins sampling, not the weights, so a model can be
    # systematically blind to its own omissions. judge_model is required in
    # live/record mode (build_judge_client raises without it); replay mode
    # grades absence from recorded judge verdicts and never calls the judge.
    # judge_base_url/judge_api_key default to the draw client's endpoint
    # (ollama_base_url + "ollama" for the ollama provider, openai_base_url +
    # openai_api_key otherwise); set them to point the judge elsewhere.
    judge_model: Optional[str] = None
    judge_base_url: Optional[str] = None
    judge_api_key: Optional[str] = None

    # Automatically load from the .env file in the root directory
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

# Instantiate it once here so the rest of the app can just import this object
settings = Settings()