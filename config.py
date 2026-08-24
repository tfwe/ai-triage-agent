from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Literal, Optional

class Settings(BaseSettings):
    # Core Toggle
    llm_provider: Literal["openai", "ollama"] = "ollama"

    # OpenAI Config
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-5.6-luna"

    abuseipdb_api_key: Optional[str] = None 

    # Ollama Config
    ollama_base_url: str = "http://localhost:11434/v1"
    ollama_model: str = "llama3.1"

    # Automatically load from the .env file in the root directory
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

# Instantiate it once here so the rest of the app can just import this object
settings = Settings()
