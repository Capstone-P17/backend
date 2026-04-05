from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class VulnerabilityFinding(BaseModel):
    id: str
    type: str
    severity: Literal["HIGH", "MEDIUM", "LOW"]
    file: str
    line: int
    function: str | None = None
    code_snippet: str
    call_chain: list[str] = Field(default_factory=list)
    description: str = ""


class SecurityScore(BaseModel):
    overall: int
    by_file: dict[str, int] = Field(default_factory=dict)


class SecurityAnalysisSummary(BaseModel):
    total_vulnerabilities: int
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_type: dict[str, int] = Field(default_factory=dict)
    score: SecurityScore


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
