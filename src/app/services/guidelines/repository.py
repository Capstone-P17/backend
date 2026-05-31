from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from src.app.core.config import PROJECT_ROOT
from src.app.services.guidelines.models import GuidelineReference


DEFAULT_REFERENCES_PATH = (
    PROJECT_ROOT / "src" / "app" / "resources" / "guidelines" / "software-security-guide-2019" / "references.json"
)


class GuidelineRepository:
    """In-memory lookup over structured guideline references."""

    def __init__(self, references: list[GuidelineReference]) -> None:
        self.references = references

    @classmethod
    def load(cls, path: Path = DEFAULT_REFERENCES_PATH) -> "GuidelineRepository":
        payload = json.loads(path.read_text(encoding="utf-8"))
        references = [GuidelineReference.from_raw(raw) for raw in payload.get("references", [])]
        return cls(references)

    def find_for_finding(self, finding: dict[str, Any]) -> list[GuidelineReference]:
        detector_type = _normalize(finding.get("type"))
        guide_item = _normalize(finding.get("guide_item"))
        guide_category = _normalize(finding.get("guide_category"))

        matches: list[tuple[int, GuidelineReference]] = []
        for reference in self.references:
            score = 0
            if detector_type and detector_type in {_normalize(value) for value in reference.detector_types}:
                score += 100
            if guide_item and guide_item == _normalize(reference.item):
                score += 30

            # Category alone is too broad for citation grounding. For example, an
            # SQL injection finding belongs to "입력데이터 검증 및 표현", but that
            # category also contains XSS, path traversal, command injection, and
            # many other unrelated guide sections. Use category only as a
            # tie-breaker once a detector/item-specific signal matched.
            if score <= 0:
                continue
            if guide_category and guide_category == _normalize(reference.category):
                score += 5
            matches.append((score, reference))

        matches.sort(key=lambda match: (-match[0], match[1].page_start, match[1].id))
        return [reference for _, reference in matches]

    def find_by_detector_type(self, detector_type: str) -> list[GuidelineReference]:
        normalized = _normalize(detector_type)
        return [
            reference
            for reference in self.references
            if normalized in {_normalize(value) for value in reference.detector_types}
        ]


@lru_cache
def get_guideline_repository() -> GuidelineRepository:
    return GuidelineRepository.load()


def _normalize(value: Any) -> str:
    return str(value or "").strip().casefold()
