from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable
from uuid import uuid4

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from src.app.models.analysis_result import AnalysisResult as AnalysisResultModel


class AnalysisResultStore:
    """In-memory analysis result store keyed by generated analysis_id."""

    def __init__(self) -> None:
        self._results: dict[str, dict[str, Any]] = {}
        self._order: list[str] = []
        self.latest_analysis_id: str | None = None

    def save(self, result: dict[str, Any]) -> str:
        analysis_id = str(uuid4())
        self._results[analysis_id] = self._clone(result)
        self._order.append(analysis_id)
        self.latest_analysis_id = analysis_id
        return analysis_id

    def get(self, analysis_id: str) -> dict[str, Any] | None:
        result = self._results.get(analysis_id)
        if result is None:
            return None
        return self._clone(result)

    def get_latest(self) -> tuple[str, dict[str, Any]] | None:
        if self.latest_analysis_id is None:
            return None
        latest = self.get(self.latest_analysis_id)
        if latest is None:
            return None
        return self.latest_analysis_id, latest

    def list_results(self, limit: int = 20) -> list[dict[str, Any]]:
        safe_limit = max(0, limit)
        return [
            self._build_summary_item(analysis_id, self._results[analysis_id])
            for analysis_id in reversed(self._order[-safe_limit:] if safe_limit else [])
            if analysis_id in self._results
        ]

    @classmethod
    def _clone(cls, result: dict[str, Any]) -> dict[str, Any]:
        return deepcopy(result)

    @classmethod
    def _build_summary_item(cls, analysis_id: str, result: dict[str, Any]) -> dict[str, Any]:
        analysis = result.get("analysis_result", {}) if isinstance(result, dict) else {}
        summary = analysis.get("summary", {}) if isinstance(analysis, dict) else {}
        return {
            "analysis_id": analysis_id,
            "repository": analysis.get("repository", "") if isinstance(analysis, dict) else "",
            "target_path": analysis.get("target_path") if isinstance(analysis, dict) else None,
            "analyzed_at": analysis.get("analyzed_at", "") if isinstance(analysis, dict) else "",
            "language": analysis.get("language", "java") if isinstance(analysis, dict) else "java",
            "files_analyzed": analysis.get("files_analyzed", 0) if isinstance(analysis, dict) else 0,
            "total_vulnerabilities": summary.get("total_vulnerabilities", 0) if isinstance(summary, dict) else 0,
            "severity_counts": dict(summary.get("by_severity", {})) if isinstance(summary, dict) else {},
        }


class DatabaseAnalysisResultStore:
    """SQLAlchemy-backed store with the same public behavior as AnalysisResultStore."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def save(self, result: dict[str, Any]) -> str:
        analysis_id = str(uuid4())
        analysis = result.get("analysis_result", {})
        summary = analysis.get("summary", {}) if isinstance(analysis, dict) else {}
        record = AnalysisResultModel(
            analysis_id=analysis_id,
            repository=analysis.get("repository") or None if isinstance(analysis, dict) else None,
            target_path=analysis.get("target_path") if isinstance(analysis, dict) else None,
            language=analysis.get("language", "java") if isinstance(analysis, dict) else "java",
            files_analyzed=analysis.get("files_analyzed", 0) if isinstance(analysis, dict) else 0,
            total_vulnerabilities=summary.get("total_vulnerabilities", 0) if isinstance(summary, dict) else 0,
            result_json=deepcopy(result),
        )
        with self._session_factory() as session:
            session.add(record)
            session.commit()
        return analysis_id

    def get(self, analysis_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            record = session.scalar(
                select(AnalysisResultModel).where(AnalysisResultModel.analysis_id == analysis_id)
            )
            if record is None:
                return None
            return deepcopy(record.result_json)

    def get_latest(self) -> tuple[str, dict[str, Any]] | None:
        with self._session_factory() as session:
            record = session.scalar(
                select(AnalysisResultModel).order_by(
                    desc(AnalysisResultModel.created_at),
                    desc(AnalysisResultModel.id),
                ).limit(1)
            )
            if record is None:
                return None
            return record.analysis_id, deepcopy(record.result_json)

    def list_results(self, limit: int = 20) -> list[dict[str, Any]]:
        safe_limit = max(0, limit)
        if safe_limit == 0:
            return []
        with self._session_factory() as session:
            records = session.scalars(
                select(AnalysisResultModel).order_by(
                    desc(AnalysisResultModel.created_at),
                    desc(AnalysisResultModel.id),
                ).limit(safe_limit)
            ).all()
            return [self._build_summary_item(record) for record in records]

    @staticmethod
    def _build_summary_item(record: AnalysisResultModel) -> dict[str, Any]:
        result = record.result_json or {}
        analysis = result.get("analysis_result", {}) if isinstance(result, dict) else {}
        summary = analysis.get("summary", {}) if isinstance(analysis, dict) else {}
        return {
            "analysis_id": record.analysis_id,
            "repository": record.repository or "",
            "target_path": record.target_path,
            "analyzed_at": analysis.get("analyzed_at", "") if isinstance(analysis, dict) else "",
            "language": record.language,
            "files_analyzed": record.files_analyzed,
            "total_vulnerabilities": record.total_vulnerabilities,
            "severity_counts": dict(summary.get("by_severity", {})) if isinstance(summary, dict) else {},
        }
