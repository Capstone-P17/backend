from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable
from uuid import uuid4

from loguru import logger
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from src.app.models.analysis_result import AnalysisResult as AnalysisResultModel


class AnalysisResultStore:
    """In-memory analysis result store keyed by generated analysis_id."""

    def __init__(self) -> None:
        self._results: dict[str, dict[str, Any]] = {}
        self._owners: dict[str, int] = {}
        self._order: list[str] = []
        self._latest_analysis_id_by_user: dict[int, str] = {}

    def save(self, result: dict[str, Any], user_id: int) -> str:
        analysis_id = str(uuid4())
        self._results[analysis_id] = self._clone(result)
        self._owners[analysis_id] = user_id
        self._order.append(analysis_id)
        self._latest_analysis_id_by_user[user_id] = analysis_id
        logger.bind(component="result_store.memory", user_id=user_id, analysis_id=analysis_id).info(
            "analysis_result_saved analysis_id={}",
            analysis_id,
        )
        return analysis_id

    def get(self, analysis_id: str, user_id: int) -> dict[str, Any] | None:
        if self._owners.get(analysis_id) != user_id:
            return None
        result = self._results.get(analysis_id)
        if result is None:
            return None
        return self._clone(result)

    def get_latest(self, user_id: int) -> tuple[str, dict[str, Any]] | None:
        latest_analysis_id = self._latest_analysis_id_by_user.get(user_id)
        if latest_analysis_id is None:
            return None
        latest = self.get(latest_analysis_id, user_id)
        if latest is None:
            return None
        return latest_analysis_id, latest

    def update(self, analysis_id: str, user_id: int, result: dict[str, Any]) -> dict[str, Any] | None:
        if self._owners.get(analysis_id) != user_id or analysis_id not in self._results:
            logger.bind(component="result_store.memory", user_id=user_id, analysis_id=analysis_id).warning(
                "analysis_result_update_miss analysis_id={}",
                analysis_id,
            )
            return None
        self._results[analysis_id] = self._clone(result)
        logger.bind(component="result_store.memory", user_id=user_id, analysis_id=analysis_id).info(
            "analysis_result_updated analysis_id={}",
            analysis_id,
        )
        return self._clone(self._results[analysis_id])

    def list_results(self, user_id: int, limit: int = 20) -> list[dict[str, Any]]:
        safe_limit = max(0, limit)
        matching_ids = [
            analysis_id
            for analysis_id in self._order
            if analysis_id in self._results and self._owners.get(analysis_id) == user_id
        ]
        return [
            self._build_summary_item(analysis_id, self._results[analysis_id])
            for analysis_id in reversed(matching_ids[-safe_limit:] if safe_limit else [])
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

    def save(self, result: dict[str, Any], user_id: int) -> str:
        analysis_id = str(uuid4())
        analysis = result.get("analysis_result", {})
        summary = analysis.get("summary", {}) if isinstance(analysis, dict) else {}
        record = AnalysisResultModel(
            user_id=user_id,
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
        logger.bind(component="result_store.db", user_id=user_id, analysis_id=analysis_id).info(
            "analysis_result_saved analysis_id={}",
            analysis_id,
        )
        return analysis_id

    def get(self, analysis_id: str, user_id: int) -> dict[str, Any] | None:
        with self._session_factory() as session:
            record = session.scalar(
                select(AnalysisResultModel).where(
                    AnalysisResultModel.analysis_id == analysis_id,
                    AnalysisResultModel.user_id == user_id,
                )
            )
            if record is None:
                logger.bind(component="result_store.db", user_id=user_id, analysis_id=analysis_id).debug(
                    "analysis_result_lookup_miss analysis_id={}",
                    analysis_id,
                )
                return None
            logger.bind(component="result_store.db", user_id=user_id, analysis_id=analysis_id).debug(
                "analysis_result_lookup_hit analysis_id={}",
                analysis_id,
            )
            return deepcopy(record.result_json)

    def get_latest(self, user_id: int) -> tuple[str, dict[str, Any]] | None:
        with self._session_factory() as session:
            record = session.scalar(
                select(AnalysisResultModel)
                .where(AnalysisResultModel.user_id == user_id)
                .order_by(
                    desc(AnalysisResultModel.created_at),
                    desc(AnalysisResultModel.id),
                )
                .limit(1)
            )
            if record is None:
                logger.bind(component="result_store.db", user_id=user_id, analysis_id=analysis_id).warning(
                    "analysis_result_update_miss analysis_id={}",
                    analysis_id,
                )
                return None
            return record.analysis_id, deepcopy(record.result_json)

    def update(self, analysis_id: str, user_id: int, result: dict[str, Any]) -> dict[str, Any] | None:
        analysis = result.get("analysis_result", {}) if isinstance(result, dict) else {}
        summary = analysis.get("summary", {}) if isinstance(analysis, dict) else {}
        with self._session_factory() as session:
            record = session.scalar(
                select(AnalysisResultModel).where(
                    AnalysisResultModel.analysis_id == analysis_id,
                    AnalysisResultModel.user_id == user_id,
                )
            )
            if record is None:
                return None

            record.repository = analysis.get("repository") or None if isinstance(analysis, dict) else None
            record.target_path = analysis.get("target_path") if isinstance(analysis, dict) else None
            record.language = analysis.get("language", "java") if isinstance(analysis, dict) else "java"
            record.files_analyzed = analysis.get("files_analyzed", 0) if isinstance(analysis, dict) else 0
            record.total_vulnerabilities = (
                summary.get("total_vulnerabilities", 0) if isinstance(summary, dict) else 0
            )
            record.result_json = deepcopy(result)
            session.commit()
            logger.bind(component="result_store.db", user_id=user_id, analysis_id=analysis_id).info(
                "analysis_result_updated analysis_id={}",
                analysis_id,
            )
            return deepcopy(record.result_json)

    def list_results(self, user_id: int, limit: int = 20) -> list[dict[str, Any]]:
        safe_limit = max(0, limit)
        if safe_limit == 0:
            return []
        with self._session_factory() as session:
            records = session.scalars(
                select(AnalysisResultModel)
                .where(AnalysisResultModel.user_id == user_id)
                .order_by(
                    desc(AnalysisResultModel.created_at),
                    desc(AnalysisResultModel.id),
                )
                .limit(safe_limit)
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
