from __future__ import annotations

from src.app.services.guidelines.repository import GuidelineRepository
from src.app.services.static_analysis.detectors.metadata import DETECTOR_METADATA


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
    assert [ref.item for ref in refs] == ["SQL 삽입"]


def test_guideline_repository_does_not_match_category_only() -> None:
    repository = GuidelineRepository.load()

    refs = repository.find_for_finding(
        {
            "type": "UNKNOWN",
            "guide_category": "입력데이터 검증 및 표현",
        }
    )

    assert refs == []


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


def test_all_detector_metadata_types_are_mapped_to_official_guideline() -> None:
    repository = GuidelineRepository.load()

    for detector_type in DETECTOR_METADATA:
        assert repository.find_by_detector_type(detector_type), detector_type


def test_guideline_reference_detector_types_are_known_by_metadata() -> None:
    repository = GuidelineRepository.load()
    known_detector_types = set(DETECTOR_METADATA)

    mapped_detector_types = {
        detector_type
        for reference in repository.references
        for detector_type in reference.detector_types
    }

    assert mapped_detector_types <= known_detector_types
