from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class GuidelineCitation(BaseModel):
    source: str
    version: str
    page_start: int
    page_end: int
    section: str


class GuidelineReference(BaseModel):
    id: str
    source_title: str
    source_version: str
    source_file: str
    category: str
    item: str
    page_start: int
    page_end: int
    detector_types: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    overview: str = ""
    security_measures: str = ""
    diagnosis: str = ""
    code_examples: str = ""
    references: str = ""
    citations: list[GuidelineCitation] = Field(default_factory=list)

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "GuidelineReference":
        source = raw.get("source", {})
        scope = raw.get("scope", {})
        mapping = raw.get("mapping", {})
        content = raw.get("content", {})
        return cls(
            id=str(raw.get("id", "")),
            source_title=str(source.get("title", "")),
            source_version=str(source.get("version", "")),
            source_file=str(source.get("source_file", "")),
            category=str(scope.get("category", "")),
            item=str(scope.get("item", "")),
            page_start=int(scope.get("page_start", 0)),
            page_end=int(scope.get("page_end", 0)),
            detector_types=[str(value) for value in mapping.get("detector_types", [])],
            cwe=[str(value) for value in mapping.get("cwe", [])],
            aliases=[str(value) for value in mapping.get("aliases", [])],
            overview=str(content.get("overview", "")),
            security_measures=str(content.get("security_measures", "")),
            diagnosis=str(content.get("diagnosis", "")),
            code_examples=str(content.get("code_examples", "")),
            references=str(content.get("references", "")),
            citations=[GuidelineCitation.model_validate(citation) for citation in raw.get("citations", [])],
        )

    def to_finding_payload(self) -> dict[str, Any]:
        """Return the compact but source-grounded payload attached to findings."""
        return {
            "id": self.id,
            "source_title": self.source_title,
            "source_version": self.source_version,
            "source_file": self.source_file,
            "category": self.category,
            "item": self.item,
            "page_start": self.page_start,
            "page_end": self.page_end,
            "detector_types": self.detector_types,
            "cwe": self.cwe,
            "overview": self.overview,
            "security_measures": self.security_measures,
            "diagnosis": self.diagnosis,
            "citations": [citation.model_dump() for citation in self.citations],
        }

    def to_llm_brief(self, *, max_chars_per_section: int = 1200) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source_title,
            "version": self.source_version,
            "section": f"{self.category} - {self.item}",
            "pages": [self.page_start, self.page_end],
            "overview": _truncate(self.overview, max_chars=max_chars_per_section),
            "security_measures": _truncate(self.security_measures, max_chars=max_chars_per_section),
            "diagnosis": _truncate(self.diagnosis, max_chars=max_chars_per_section),
            "citations": [citation.model_dump() for citation in self.citations],
        }


def _truncate(value: str, *, max_chars: int) -> str:
    if max_chars <= 0 or len(value) <= max_chars:
        return value
    return f"{value[:max_chars].rstrip()}…"
