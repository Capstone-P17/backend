from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
Confidence = Literal["HIGH", "MEDIUM", "LOW"]
LLMReportStatus = Literal["unavailable", "generated", "failed"]


class CvssInfo(BaseModel):
    score: float | None = None
    vector: str | None = None


class VulnerabilityFinding(BaseModel):
    id: str
    type: str
    severity: Severity
    cwe: str
    guide_source: str
    guide_category: str
    guide_item: str
    cvss: CvssInfo | None = None
    file: str
    line: int | None = None
    function: str | None = None
    code_snippet: str | None = None
    call_chain: list[str] = Field(default_factory=list)
    evidence: str = ""
    description: str
    recommendation: str
    safe_example: str
    confidence: Confidence
    confidence_reason: str = ""


class SecurityScore(BaseModel):
    overall: int
    by_file: dict[str, int] = Field(default_factory=dict)


class AnalysisSummary(BaseModel):
    total_vulnerabilities: int
    by_type: dict[str, int] = Field(default_factory=dict)
    by_guide_category: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    score: SecurityScore


class AnalysisResult(BaseModel):
    repository: str = ""
    target_path: str | None = None
    analyzed_at: str
    language: str = "java"
    files_analyzed: int
    vulnerabilities: list[VulnerabilityFinding] = Field(default_factory=list)
    call_graph: dict[str, list[str]] = Field(default_factory=dict)
    summary: AnalysisSummary
    llm_report: str | None = None
    llm_report_status: LLMReportStatus = "unavailable"
    llm_report_available: bool = False
    llm_report_error: str | None = None
    llm_model: str | None = None


class AnalysisResponse(BaseModel):
    analysis_id: str
    analysis_result: AnalysisResult


class FileAnalysisSummary(BaseModel):
    total_vulnerabilities: int
    by_type: dict[str, int] = Field(default_factory=dict)
    by_guide_category: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    score: int | None = None


class FileAnalysisResponse(BaseModel):
    analysis_id: str
    file_id: str
    file_path: str
    repository: str = ""
    analyzed_at: str
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    summary: FileAnalysisSummary


class AnalysisResultListItem(BaseModel):
    analysis_id: str
    repository: str
    target_path: str | None = None
    analyzed_at: str
    language: str
    files_analyzed: int
    total_vulnerabilities: int
    severity_counts: dict[str, int] = Field(default_factory=dict)


class AnalysisResultListResponse(BaseModel):
    results: list[AnalysisResultListItem] = Field(default_factory=list)
