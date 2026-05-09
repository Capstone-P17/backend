from __future__ import annotations

from uuid import UUID

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.app.db.base import Base
from src.app.models.analysis_result import AnalysisResult  # noqa: F401
from src.app.services.result_store import AnalysisResultStore, DatabaseAnalysisResultStore


def sample_result(repository: str = "repo", total: int = 1) -> dict:
    return {
        "analysis_result": {
            "repository": repository,
            "target_path": "src",
            "analyzed_at": "2026-01-01T00:00:00",
            "language": "java",
            "files_analyzed": 2,
            "vulnerabilities": [],
            "call_graph": {"a": ["b"]},
            "summary": {
                "total_vulnerabilities": total,
                "by_type": {},
                "by_severity": {"HIGH": total},
                "score": {"overall": 90, "by_file": {}},
            },
        }
    }


def assert_store_contract(store) -> None:
    assert store.get_latest() is None
    first_id = store.save(sample_result("first", 1))
    second_id = store.save(sample_result("second", 2))
    UUID(first_id)
    UUID(second_id)
    assert first_id != second_id
    assert store.get(first_id)["analysis_result"]["repository"] == "first"
    latest_id, latest = store.get_latest()
    assert latest_id == second_id
    assert latest["analysis_result"]["repository"] == "second"
    summaries = store.list_results(limit=1)
    assert len(summaries) == 1
    assert summaries[0]["analysis_id"] == second_id
    assert summaries[0]["total_vulnerabilities"] == 2
    assert store.get("missing") is None


def test_in_memory_result_store_contract() -> None:
    assert_store_contract(AnalysisResultStore())


def test_database_result_store_persists_across_instances(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    store = DatabaseAnalysisResultStore(SessionLocal)
    analysis_id = store.save(sample_result("persisted", 3))

    new_store = DatabaseAnalysisResultStore(SessionLocal)
    assert new_store.get(analysis_id)["analysis_result"]["repository"] == "persisted"
    latest_id, _ = new_store.get_latest()
    assert latest_id == analysis_id
    assert new_store.list_results()[0]["analysis_id"] == analysis_id
