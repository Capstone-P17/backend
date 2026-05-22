from __future__ import annotations

from src.app.services.guidelines.repository import GuidelineRepository


def test_guideline_repository_maps_detector_type_to_reference() -> None:
    repository = GuidelineRepository.load()

    refs = repository.find_for_finding(
        {
            "type": "SQL_INJECTION",
            "cwe": "CWE-89",
            "guide_category": "입력데이터 검증 및 표현",
            "guide_item": "SQL 삽입",
        }
    )

    assert refs
    assert refs[0].item == "SQL 삽입"
    assert refs[0].page_start == 178
    assert refs[0].page_end == 191
    assert "PreparedStatement" in refs[0].security_measures


def test_guideline_repository_returns_multiple_refs_for_broad_detector_type() -> None:
    repository = GuidelineRepository.load()

    refs = repository.find_by_detector_type("WEAK_HASH")

    assert {ref.item for ref in refs} == {
        "취약한 암호화 알고리즘 사용",
        "솔트 없이 일방향 해시함수 사용",
    }


def test_guideline_repository_returns_empty_for_unknown_finding() -> None:
    repository = GuidelineRepository.load()

    assert repository.find_for_finding({"type": "UNKNOWN"}) == []
