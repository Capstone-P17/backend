from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from src.app.schemas.analysis import AnalysisSummary as SecurityAnalysisSummary
from src.app.schemas.analysis import VulnerabilityFinding


class AgentRunRequest(BaseModel):
    session_id: str | None = None
    user_id: str | None = None
    target_path: str = Field(min_length=1)
    repository: str | None = None
    instructions: str | None = Field(default=None, max_length=4000)
    include_raw_analysis: bool = False


class AgentRunResponse(BaseModel):
    agent_name: str
    session_id: str
    target_path: str
    summary: str
    report: str
    trace: list[str] = Field(default_factory=list)
    analysis_summary: SecurityAnalysisSummary
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    raw_analysis: dict[str, Any] | None = None


class AgentProfileResponse(BaseModel):
    agent_name: str
    environment: str
    api_prefix: str
    llm_provider: str
    llm_model: str
    graph_nodes: list[str]
    capabilities: list[str]
    default_target_path: str
    openai_configured: bool
    llm_report_available: bool
