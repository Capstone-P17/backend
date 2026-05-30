from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


JobStatus = Literal["queued", "running", "succeeded", "failed"]
JobPhase = Literal[
    "queued",
    "preparing",
    "cloning",
    "indexing",
    "static_analysis",
    "finding_validation",
    "report_generation",
    "summary_generation",
    "saving",
    "succeeded",
    "failed",
]


class AnalysisJobProgress(BaseModel):
    percent: int = 0
    files_analyzed: int = 0
    files_total: int = 0
    findings_total: int = 0
    finding_reports_completed: int = 0
    finding_reports_total: int = 0


class AnalysisJobCreateResponse(BaseModel):
    job_id: str
    status: JobStatus


class AnalysisJobStatusResponse(BaseModel):
    job_id: str
    status: JobStatus
    phase: JobPhase | str = "queued"
    message: str = ""
    progress: AnalysisJobProgress = Field(default_factory=AnalysisJobProgress)
    analysis_id: str | None = None
    error: str | None = None
    created_at: str
    updated_at: str
