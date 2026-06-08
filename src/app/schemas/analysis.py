from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


Confidence = Literal["HIGH", "MEDIUM", "LOW"]
LLMReportStatus = Literal["unavailable", "generated", "failed", "skipped_context_budget_exceeded"]
FindingReportStatus = Literal[
    "unavailable",
    "generated",
    "static_fallback",
    "failed",
    "skipped_context_budget_exceeded",
]
FindingReportSource = Literal["llm", "static_fallback"]
GuidelineGroundingStatus = Literal["matched", "missing", "ambiguous"]
FindingAnalysisStatus = Literal["confirmed", "needs_review"]
LLMExplanationStatus = Literal["unavailable", "generated", "skipped", "failed", "skipped_context_budget_exceeded"]


class GuidelineCitation(BaseModel):
    source: str
    version: str
    page_start: int
    page_end: int
    section: str


class GuidelineReference(BaseModel):
    id: str
    source_title: str
    source_version: str
    source_file: str
    category: str
    item: str
    page_start: int
    page_end: int
    detector_types: list[str] = Field(default_factory=list)
    overview: str = ""
    security_measures: str = ""
    diagnosis: str = ""
    citations: list[GuidelineCitation] = Field(default_factory=list)


class FindingLLMExplanation(BaseModel):
    why_vulnerable: str
    how_to_fix: str
    fix_steps: list[str] = Field(default_factory=list)
    cited_guideline_ids: list[str] = Field(default_factory=list)
    citations: list[GuidelineCitation] = Field(default_factory=list)
    grounding_notes: str | None = None


class FindingReportMetadata(BaseModel):
    title: str
    generated_at: str | None = None
    model: str | None = None
    prompt_chars: int | None = None
    source: FindingReportSource = "static_fallback"


class FindingMarkdownReport(BaseModel):
    status: FindingReportStatus = "unavailable"
    title: str = ""
    summary: str = ""
    markdown: str = ""
    proposed_patch: str | None = None
    metadata: FindingReportMetadata | None = None
    error: str | None = None


class CallChainDetail(BaseModel):
    label: str
    kind: str = "unknown"
    file: str | None = None
    line: int | None = None
    function: str | None = None
    source_url: str | None = None
    source_ref: str | None = None
    source_link: str | None = None


class VulnerabilityFinding(BaseModel):
    id: str
    type: str
    guide_source: str
    guide_category: str
    guide_item: str
    cwe: str = ""
    file: str
    line: int | None = None
    function: str | None = None
    source_url: str | None = None
    source_ref: str | None = None
    source_link: str | None = None
    code_snippet: str | None = None
    call_chain: list[str] = Field(default_factory=list)
    call_chain_details: list[CallChainDetail] = Field(default_factory=list)
    evidence: str = ""
    description: str
    recommendation: str
    safe_example: str
    confidence: Confidence
    confidence_reason: str = ""
    guideline_refs: list[GuidelineReference] = Field(default_factory=list)
    guideline_grounding_status: GuidelineGroundingStatus = "missing"
    analysis_status: FindingAnalysisStatus = "needs_review"
    llm_explanation_status: LLMExplanationStatus = "unavailable"
    llm_explanation: FindingLLMExplanation | None = None
    llm_explanation_error: str | None = None
    finding_report_status: FindingReportStatus = "unavailable"
    finding_report_title: str = ""
    finding_report_summary: str = ""
    finding_report_markdown_preview: str = ""
    finding_report: FindingMarkdownReport | None = None
    duplicate_count: int = 1
    related_finding_ids: list[str] = Field(default_factory=list)


class SecurityScore(BaseModel):
    overall: int
    by_file: dict[str, int] = Field(default_factory=dict)


class AnalysisSummary(BaseModel):
    total_vulnerabilities: int
    by_type: dict[str, int] = Field(default_factory=dict)
    by_guide_category: dict[str, int] = Field(default_factory=dict)
    score: SecurityScore


class AnalysisResult(BaseModel):
    repository: str = ""
    target_path: str | None = None
    source_url: str | None = None
    source_ref: str | None = None
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
    score: int | None = None


class FileAnalysisResponse(BaseModel):
    analysis_id: str
    file_id: str
    file_path: str
    repository: str = ""
    analyzed_at: str
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    summary: FileAnalysisSummary


class FindingDetailResponse(BaseModel):
    analysis_id: str
    repository: str = ""
    analyzed_at: str = ""
    finding: VulnerabilityFinding


class AnalysisResultListItem(BaseModel):
    analysis_id: str
    owner_user_id: int | None = None
    is_public: bool = False
    repository: str
    target_path: str | None = None
    analyzed_at: str
    language: str
    files_analyzed: int
    total_vulnerabilities: int


class AnalysisResultListResponse(BaseModel):
    results: list[AnalysisResultListItem] = Field(default_factory=list)
