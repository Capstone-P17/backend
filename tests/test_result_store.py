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
                "score": {"overall": 90, "by_file": {}},
            },
        }
    }


def assert_store_contract(store) -> None:
    assert store.get_latest(user_id=1) is None
    first_id = store.save(sample_result("first", 1), user_id=1)
    second_id = store.save(sample_result("second", 2), user_id=1)
    third_id = store.save(sample_result("other", 4), user_id=2)
    UUID(first_id)
    UUID(second_id)
    UUID(third_id)
    assert first_id != second_id
    assert store.get(first_id, user_id=1)["analysis_result"]["repository"] == "first"
    assert store.get(first_id, user_id=2) is None
    latest_id, latest = store.get_latest(user_id=1)
    assert latest_id == second_id
    assert latest["analysis_result"]["repository"] == "second"
    latest_other_id, latest_other = store.get_latest(user_id=2)
    assert latest_other_id == third_id
    assert latest_other["analysis_result"]["repository"] == "other"
    summaries = store.list_results(user_id=1, limit=1)
    assert len(summaries) == 1
    assert summaries[0]["analysis_id"] == second_id
    assert summaries[0]["total_vulnerabilities"] == 2
    assert store.list_results(user_id=2)[0]["analysis_id"] == third_id
    assert store.get("missing", user_id=1) is None


def test_in_memory_result_store_contract() -> None:
    assert_store_contract(AnalysisResultStore())


def test_database_result_store_persists_across_instances(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    store = DatabaseAnalysisResultStore(SessionLocal)
    analysis_id = store.save(sample_result("persisted", 3), user_id=7)

    new_store = DatabaseAnalysisResultStore(SessionLocal)
    assert new_store.get(analysis_id, user_id=7)["analysis_result"]["repository"] == "persisted"
    assert new_store.get(analysis_id, user_id=1) is None
    latest_id, _ = new_store.get_latest(user_id=7)
    assert latest_id == analysis_id
    assert new_store.list_results(user_id=7)[0]["analysis_id"] == analysis_id


def assert_update_contract(store) -> None:
    analysis_id = store.save(sample_result("before", 1), user_id=11)
    updated = sample_result("after", 5)
    persisted = store.update(analysis_id, user_id=11, result=updated)
    assert persisted is not None
    assert persisted["analysis_result"]["repository"] == "after"
    assert store.get(analysis_id, user_id=11)["analysis_result"]["summary"]["total_vulnerabilities"] == 5
    assert store.update(analysis_id, user_id=99, result=sample_result("wrong-owner", 9)) is None
    assert store.get(analysis_id, user_id=11)["analysis_result"]["repository"] == "after"
    assert store.update("missing", user_id=11, result=updated) is None


def test_in_memory_result_store_update_persists_owner_scoped_results() -> None:
    assert_update_contract(AnalysisResultStore())


def test_database_result_store_update_persists_owner_scoped_results(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'update.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    assert_update_contract(DatabaseAnalysisResultStore(SessionLocal))


def assert_visibility_contract(store) -> None:
    analysis_id = store.save(sample_result("shared", 7), user_id=21)

    assert store.get(analysis_id, user_id=99) is None
    assert store.set_visibility(analysis_id, is_public=True) == {
        "analysis_id": analysis_id,
        "owner_user_id": 21,
        "is_public": True,
    }
    assert store.get(analysis_id, user_id=99)["analysis_result"]["repository"] == "shared"
    public_summaries = store.list_results(user_id=99)
    assert public_summaries[0]["analysis_id"] == analysis_id
    assert public_summaries[0]["owner_user_id"] == 21
    assert public_summaries[0]["is_public"] is True
    latest_id, latest = store.get_latest(user_id=99)
    assert latest_id == analysis_id
    assert latest["analysis_result"]["repository"] == "shared"

    assert store.set_visibility(analysis_id, is_public=False) == {
        "analysis_id": analysis_id,
        "owner_user_id": 21,
        "is_public": False,
    }
    assert store.get(analysis_id, user_id=99) is None
    assert store.set_visibility("missing", is_public=True) is None


def test_in_memory_result_store_visibility_policy() -> None:
    assert_visibility_contract(AnalysisResultStore())


def test_database_result_store_visibility_policy(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'visibility.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    assert_visibility_contract(DatabaseAnalysisResultStore(SessionLocal))
