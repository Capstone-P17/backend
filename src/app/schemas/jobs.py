from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


JobStatus = Literal["queued", "running", "succeeded", "failed"]


class AnalysisJobCreateResponse(BaseModel):
    job_id: str
    status: JobStatus


class AnalysisJobStatusResponse(BaseModel):
    job_id: str
    status: JobStatus
    analysis_id: str | None = None
    error: str | None = None
    created_at: str
    updated_at: str
