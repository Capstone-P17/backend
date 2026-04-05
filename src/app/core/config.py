from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ANALYSIS_TARGET = PROJECT_ROOT / "src" / "analyzer" / "test_samples"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="AGENT_",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "AI Security Audit Backend"
    app_version: str = "1.0.0"
    environment: Literal["local", "dev", "prod"] = "local"
    api_prefix: str = ""

    host: str = "0.0.0.0"
    port: int = 8000
    reload: bool = False

    workspace_root: Path = PROJECT_ROOT
    analysis_default_target: Path = DEFAULT_ANALYSIS_TARGET
    analysis_max_findings_in_prompt: int = 20

    default_agent_name: str = "security-audit-agent"
    default_system_prompt: str = (
        "You are a senior application security analyst. Use the provided static-analysis results "
        "to write a concise but actionable Korean report for developers."
    )
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"
    openai_temperature: float = 0.1
    allowed_origins: list[str] = Field(default_factory=lambda: ["*"])


@lru_cache
def get_settings() -> Settings:
    return Settings()
