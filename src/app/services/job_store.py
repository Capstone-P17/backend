from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

JobStatus = Literal["queued", "running", "succeeded", "failed"]


class AnalysisJobStore:
    """In-memory store for repository analysis jobs."""

    def __init__(self) -> None:
        self._jobs: dict[str, dict[str, Any]] = {}

    def create(self) -> dict[str, Any]:
        now = self._now()
        job = {
            "job_id": str(uuid4()),
            "status": "queued",
            "phase": "queued",
            "message": "분석 작업이 대기열에 등록되었습니다.",
            "progress": {
                "percent": 0,
                "files_analyzed": 0,
                "files_total": 0,
                "findings_total": 0,
                "finding_reports_completed": 0,
                "finding_reports_total": 0,
            },
            "analysis_id": None,
            "error": None,
            "created_at": now,
            "updated_at": now,
        }
        self._jobs[job["job_id"]] = deepcopy(job)
        return deepcopy(job)

    def get(self, job_id: str) -> dict[str, Any] | None:
        job = self._jobs.get(job_id)
        if job is None:
            return None
        return deepcopy(job)

    def update(
        self,
        job_id: str,
        *,
        status: JobStatus,
        analysis_id: str | None = None,
        error: str | None = None,
        phase: str | None = None,
        message: str | None = None,
        progress: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        job = self._jobs.get(job_id)
        if job is None:
            return None
        job["status"] = status
        if phase is not None:
            job["phase"] = phase
        if message is not None:
            job["message"] = message
        if progress is not None:
            current_progress = job.get("progress")
            if not isinstance(current_progress, dict):
                current_progress = {}
            current_progress.update(progress)
            job["progress"] = current_progress
        job["analysis_id"] = analysis_id
        job["error"] = error
        job["updated_at"] = self._now()
        return deepcopy(job)

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()
