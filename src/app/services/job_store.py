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
    ) -> dict[str, Any] | None:
        job = self._jobs.get(job_id)
        if job is None:
            return None
        job["status"] = status
        job["analysis_id"] = analysis_id
        job["error"] = error
        job["updated_at"] = self._now()
        return deepcopy(job)

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()
