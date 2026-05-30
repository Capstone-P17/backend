import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator

PROJECT_ROOT = Path(__file__).resolve().parents[3]
ENV_FILE = PROJECT_ROOT / ".env"
DEFAULT_ANALYSIS_TARGET = PROJECT_ROOT / "src" / "analyzer" / "test_samples"
DEFAULT_SYSTEM_PROMPT = (
    "You are a senior application security analyst. Use the provided static-analysis results "
    "to write a concise but actionable Korean report for developers."
)
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_MAX_UPLOAD_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_ARCHIVE_MEMBERS = 5000


class Settings(BaseModel):
    """Application settings loaded from code configuration and environment variables."""

    model_config = ConfigDict(
        extra="ignore",
        populate_by_name=True,
    )

    app_name: str = Field(
        default="AI Security Audit Backend",
        validation_alias=AliasChoices("APP_NAME", "AGENT_APP_NAME"),
    )
    app_version: str = Field(
        default="1.0.0",
        validation_alias=AliasChoices("APP_VERSION", "AGENT_APP_VERSION"),
    )
    environment: Literal["local", "dev", "prod"] = Field(
        default="local",
        validation_alias=AliasChoices("ENVIRONMENT", "AGENT_ENVIRONMENT"),
    )
    api_prefix: str = Field(
        default="", validation_alias=AliasChoices("API_PREFIX", "AGENT_API_PREFIX")
    )

    host: str = Field(
        default="0.0.0.0", validation_alias=AliasChoices("HOST", "AGENT_HOST")
    )
    port: int = Field(default=8000, validation_alias=AliasChoices("PORT", "AGENT_PORT"))
    reload: bool = Field(
        default=False, validation_alias=AliasChoices("RELOAD", "AGENT_RELOAD")
    )
    docs_enabled: bool = Field(
        default=True, validation_alias=AliasChoices("DOCS_ENABLED", "AGENT_DOCS_ENABLED")
    )
    log_level: str = Field(
        default="INFO",
        validation_alias=AliasChoices("LOG_LEVEL", "AGENT_LOG_LEVEL"),
    )
    log_colorize: bool = Field(
        default=True,
        validation_alias=AliasChoices("LOG_COLORIZE", "AGENT_LOG_COLORIZE"),
    )
    log_json: bool = Field(
        default=False,
        validation_alias=AliasChoices("LOG_JSON", "AGENT_LOG_JSON"),
    )
    log_backtrace: bool = Field(
        default=False,
        validation_alias=AliasChoices("LOG_BACKTRACE", "AGENT_LOG_BACKTRACE"),
    )
    log_diagnose: bool = Field(
        default=False,
        validation_alias=AliasChoices("LOG_DIAGNOSE", "AGENT_LOG_DIAGNOSE"),
    )
    log_file_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("LOG_FILE_ENABLED", "AGENT_LOG_FILE_ENABLED"),
    )
    log_file_path: str = Field(
        default="logs/backend.log",
        validation_alias=AliasChoices("LOG_FILE_PATH", "AGENT_LOG_FILE_PATH"),
    )
    log_file_rotation: str = Field(
        default="10 MB",
        validation_alias=AliasChoices("LOG_FILE_ROTATION", "AGENT_LOG_FILE_ROTATION"),
    )
    log_file_retention: str = Field(
        default="14 days",
        validation_alias=AliasChoices("LOG_FILE_RETENTION", "AGENT_LOG_FILE_RETENTION"),
    )
    log_file_compression: str = Field(
        default="gz",
        validation_alias=AliasChoices("LOG_FILE_COMPRESSION", "AGENT_LOG_FILE_COMPRESSION"),
    )

    workspace_root: Path = Field(
        default=PROJECT_ROOT,
        validation_alias=AliasChoices("WORKSPACE_ROOT", "AGENT_WORKSPACE_ROOT"),
    )
    analysis_default_target: Path = Field(
        default=DEFAULT_ANALYSIS_TARGET,
        validation_alias=AliasChoices(
            "ANALYSIS_DEFAULT_TARGET", "AGENT_ANALYSIS_DEFAULT_TARGET"
        ),
    )
    analysis_max_findings_in_prompt: int = Field(
        default=20,
        validation_alias=AliasChoices(
            "ANALYSIS_MAX_FINDINGS_IN_PROMPT",
            "AGENT_ANALYSIS_MAX_FINDINGS_IN_PROMPT",
        ),
    )
    llm_guideline_overview_max_chars: int = Field(
        default=600,
        ge=0,
        validation_alias=AliasChoices(
            "LLM_GUIDELINE_OVERVIEW_MAX_CHARS",
            "AGENT_LLM_GUIDELINE_OVERVIEW_MAX_CHARS",
        ),
    )
    llm_guideline_security_measures_max_chars: int = Field(
        default=800,
        ge=0,
        validation_alias=AliasChoices(
            "LLM_GUIDELINE_SECURITY_MEASURES_MAX_CHARS",
            "AGENT_LLM_GUIDELINE_SECURITY_MEASURES_MAX_CHARS",
        ),
    )
    llm_guideline_diagnosis_max_chars: int = Field(
        default=800,
        ge=0,
        validation_alias=AliasChoices(
            "LLM_GUIDELINE_DIAGNOSIS_MAX_CHARS",
            "AGENT_LLM_GUIDELINE_DIAGNOSIS_MAX_CHARS",
        ),
    )
    llm_finding_evidence_max_chars: int = Field(
        default=800,
        ge=0,
        validation_alias=AliasChoices(
            "LLM_FINDING_EVIDENCE_MAX_CHARS",
            "AGENT_LLM_FINDING_EVIDENCE_MAX_CHARS",
        ),
    )
    llm_report_max_detailed_findings: int = Field(
        default=20,
        ge=0,
        validation_alias=AliasChoices(
            "LLM_REPORT_MAX_DETAILED_FINDINGS",
            "AGENT_LLM_REPORT_MAX_DETAILED_FINDINGS",
        ),
    )
    llm_report_max_findings_per_group: int = Field(
        default=5,
        ge=1,
        validation_alias=AliasChoices(
            "LLM_REPORT_MAX_FINDINGS_PER_GROUP",
            "AGENT_LLM_REPORT_MAX_FINDINGS_PER_GROUP",
        ),
    )
    llm_report_group_summary_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "LLM_REPORT_GROUP_SUMMARY_ENABLED",
            "AGENT_LLM_REPORT_GROUP_SUMMARY_ENABLED",
        ),
    )
    llm_report_payload_max_chars: int = Field(
        default=240_000,
        ge=0,
        validation_alias=AliasChoices(
            "LLM_REPORT_PAYLOAD_MAX_CHARS",
            "AGENT_LLM_REPORT_PAYLOAD_MAX_CHARS",
        ),
    )
    llm_finding_explanation_payload_max_chars: int = Field(
        default=24_000,
        ge=0,
        validation_alias=AliasChoices(
            "LLM_FINDING_EXPLANATION_PAYLOAD_MAX_CHARS",
            "AGENT_LLM_FINDING_EXPLANATION_PAYLOAD_MAX_CHARS",
        ),
    )
    llm_finding_detail_payload_max_chars: int = Field(
        default=32_000,
        ge=0,
        validation_alias=AliasChoices(
            "LLM_FINDING_DETAIL_PAYLOAD_MAX_CHARS",
            "AGENT_LLM_FINDING_DETAIL_PAYLOAD_MAX_CHARS",
        ),
    )
    llm_finding_detail_markdown_max_chars: int = Field(
        default=24_000,
        ge=0,
        validation_alias=AliasChoices(
            "LLM_FINDING_DETAIL_MARKDOWN_MAX_CHARS",
            "AGENT_LLM_FINDING_DETAIL_MARKDOWN_MAX_CHARS",
        ),
    )
    max_upload_bytes: int = Field(
        default=DEFAULT_MAX_UPLOAD_BYTES,
        ge=1,
        validation_alias=AliasChoices("MAX_UPLOAD_BYTES", "AGENT_MAX_UPLOAD_BYTES"),
    )
    max_archive_members: int = Field(
        default=DEFAULT_MAX_ARCHIVE_MEMBERS,
        ge=1,
        validation_alias=AliasChoices("MAX_ARCHIVE_MEMBERS", "AGENT_MAX_ARCHIVE_MEMBERS"),
    )

    default_agent_name: str = Field(
        default="security-audit-agent",
        validation_alias=AliasChoices("DEFAULT_AGENT_NAME", "AGENT_DEFAULT_AGENT_NAME"),
    )
    openai_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("OPENAI_API_KEY", "AGENT_OPENAI_API_KEY"),
    )
    openai_model: str = Field(
        default=DEFAULT_OPENAI_MODEL,
        validation_alias=AliasChoices("OPENAI_MODEL", "AGENT_OPENAI_MODEL"),
    )
    openai_temperature: float = Field(
        default=0.1,
        validation_alias=AliasChoices("OPENAI_TEMPERATURE", "AGENT_OPENAI_TEMPERATURE"),
    )
    allowed_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000"],
        validation_alias=AliasChoices("ALLOWED_ORIGINS", "AGENT_ALLOWED_ORIGINS"),
    )
    cors_allow_credentials: bool = Field(
        default=True,
        validation_alias=AliasChoices("CORS_ALLOW_CREDENTIALS", "AGENT_CORS_ALLOW_CREDENTIALS"),
    )
    database_url: str = Field(
        default=f"sqlite:///{(PROJECT_ROOT / 'app.db').as_posix()}",
        validation_alias=AliasChoices("DATABASE_URL", "AGENT_DATABASE_URL"),
    )
    jwt_secret_key: str = Field(
        default="",
        validation_alias=AliasChoices("JWT_SECRET_KEY", "AGENT_JWT_SECRET_KEY"),
    )
    jwt_algorithm: str = Field(
        default="HS256",
        validation_alias=AliasChoices("JWT_ALGORITHM", "AGENT_JWT_ALGORITHM"),
    )
    access_token_expire_minutes: int = Field(
        default=60,
        validation_alias=AliasChoices(
            "ACCESS_TOKEN_EXPIRE_MINUTES",
            "AGENT_ACCESS_TOKEN_EXPIRE_MINUTES",
        ),
    )
    frontend_auth_callback_url: str = Field(
        default="http://localhost:3000/auth/callback",
        validation_alias=AliasChoices(
            "FRONTEND_AUTH_CALLBACK_URL",
            "AGENT_FRONTEND_AUTH_CALLBACK_URL",
        ),
    )
    auth_cookie_name: str = Field(
        default="access_token",
        validation_alias=AliasChoices("AUTH_COOKIE_NAME", "AGENT_AUTH_COOKIE_NAME"),
    )
    auth_cookie_secure: bool = Field(
        default=True,
        validation_alias=AliasChoices("AUTH_COOKIE_SECURE", "AGENT_AUTH_COOKIE_SECURE"),
    )
    auth_cookie_samesite: Literal["lax", "strict", "none"] = Field(
        default="lax",
        validation_alias=AliasChoices("AUTH_COOKIE_SAMESITE", "AGENT_AUTH_COOKIE_SAMESITE"),
    )
    oauth_state_cookie_name: str = Field(
        default="github_oauth_state",
        validation_alias=AliasChoices(
            "OAUTH_STATE_COOKIE_NAME",
            "AGENT_OAUTH_STATE_COOKIE_NAME",
        ),
    )
    oauth_state_cookie_max_age_seconds: int = Field(
        default=600,
        validation_alias=AliasChoices(
            "OAUTH_STATE_COOKIE_MAX_AGE_SECONDS",
            "AGENT_OAUTH_STATE_COOKIE_MAX_AGE_SECONDS",
        ),
    )
    github_client_id: str = Field(
        default="",
        validation_alias=AliasChoices("GITHUB_CLIENT_ID", "AGENT_GITHUB_CLIENT_ID"),
    )
    github_client_secret: str = Field(
        default="",
        validation_alias=AliasChoices(
            "GITHUB_CLIENT_SECRET",
            "AGENT_GITHUB_CLIENT_SECRET",
        ),
    )
    github_redirect_uri: str = Field(
        default="http://localhost:8000/auth/github/callback",
        validation_alias=AliasChoices(
            "GITHUB_REDIRECT_URI",
            "AGENT_GITHUB_REDIRECT_URI",
        ),
    )
    github_authorize_url: str = Field(
        default="https://github.com/login/oauth/authorize",
        validation_alias=AliasChoices(
            "GITHUB_AUTHORIZE_URL",
            "AGENT_GITHUB_AUTHORIZE_URL",
        ),
    )
    github_token_url: str = Field(
        default="https://github.com/login/oauth/access_token",
        validation_alias=AliasChoices("GITHUB_TOKEN_URL", "AGENT_GITHUB_TOKEN_URL"),
    )
    github_user_api_url: str = Field(
        default="https://api.github.com/user",
        validation_alias=AliasChoices("GITHUB_USER_API_URL", "AGENT_GITHUB_USER_API_URL"),
    )

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def parse_allowed_origins(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value

        stripped = value.strip()
        if not stripped:
            return []

        if stripped.startswith("["):
            return json.loads(stripped)

        return [origin.strip() for origin in stripped.split(",") if origin.strip()]

    @field_validator("log_level", mode="before")
    @classmethod
    def normalize_log_level(cls, value: Any) -> Any:
        if isinstance(value, str):
            normalized = value.strip().upper()
            if normalized not in {"TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"}:
                raise ValueError("LOG_LEVEL must be one of TRACE, DEBUG, INFO, SUCCESS, WARNING, ERROR, CRITICAL.")
            return normalized
        return value

    @model_validator(mode="after")
    def validate_deployment_security(self) -> "Settings":
        if len(self.jwt_secret_key.encode("utf-8")) < 32:
            raise ValueError("JWT_SECRET_KEY must be set to at least 32 bytes.")

        if self.environment == "prod":
            if self.cors_allow_credentials and "*" in self.allowed_origins:
                raise ValueError(
                    "ALLOWED_ORIGINS must not contain '*' when CORS_ALLOW_CREDENTIALS=true in prod."
                )
            if not self.auth_cookie_secure:
                raise ValueError("AUTH_COOKIE_SECURE must be true in prod.")

        return self

    @property
    def default_system_prompt(self) -> str:
        return DEFAULT_SYSTEM_PROMPT

    @property
    def default_openai_model(self) -> str:
        return DEFAULT_OPENAI_MODEL


@lru_cache
def get_settings() -> Settings:
    return Settings.model_validate(_load_settings_values())


def _load_settings_values() -> dict[str, str]:
    raw_values = _read_env_file(ENV_FILE)
    raw_values.update({key.upper(): value for key, value in os.environ.items()})

    values: dict[str, str] = {}
    for field_name, field_info in Settings.model_fields.items():
        for env_name in _field_env_names(field_name, field_info.validation_alias):
            if env_name in raw_values:
                values[field_name] = raw_values[env_name]
                break
    return values


def _field_env_names(field_name: str, validation_alias: Any) -> list[str]:
    if validation_alias is None:
        return [field_name.upper()]

    choices = getattr(validation_alias, "choices", None)
    if choices is not None:
        return [str(choice).upper() for choice in choices]

    return [str(validation_alias).upper()]


def _read_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}

    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue

        key, value = stripped.split("=", 1)
        key = key.strip().upper()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key] = value
    return values
