from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class GroundingVerificationResult:
    passed: bool
    notes: list[str]


def verify_finding_explanation(
    *,
    finding: dict[str, Any],
    explanation: dict[str, Any],
) -> GroundingVerificationResult:
    """Verify an LLM explanation only cites and locates what the finding permits."""

    notes: list[str] = []
    guideline_refs = [ref for ref in finding.get("guideline_refs", []) if isinstance(ref, dict)]
    valid_ref_ids = {str(ref.get("id")) for ref in guideline_refs if ref.get("id")}
    cited_ids = {str(value) for value in explanation.get("cited_guideline_ids", [])}

    unknown_ids = cited_ids - valid_ref_ids
    if unknown_ids:
        notes.append(f"알 수 없는 guideline id 인용: {', '.join(sorted(unknown_ids))}")

    valid_citations = {
        _citation_key(citation)
        for ref in guideline_refs
        for citation in ref.get("citations", [])
        if isinstance(citation, dict)
    }
    for citation in explanation.get("citations", []):
        if not isinstance(citation, dict):
            notes.append("citation 형식이 올바르지 않습니다.")
            continue
        if _citation_key(citation) not in valid_citations:
            notes.append(f"등록되지 않은 guideline citation 인용: {_citation_label(citation)}")

    location_notes = _verify_location_claims(finding, explanation)
    notes.extend(location_notes)

    return GroundingVerificationResult(passed=not notes, notes=notes)


def _citation_key(citation: dict[str, Any]) -> tuple[str, str, int, int, str]:
    return (
        str(citation.get("source", "")),
        str(citation.get("version", "")),
        int(citation.get("page_start") or 0),
        int(citation.get("page_end") or 0),
        str(citation.get("section", "")),
    )


def _citation_label(citation: dict[str, Any]) -> str:
    source, version, page_start, page_end, section = _citation_key(citation)
    return f"{source} {version} p.{page_start}-{page_end} {section}"


def _verify_location_claims(finding: dict[str, Any], explanation: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    text = " ".join(
        str(explanation.get(field) or "")
        for field in ("why_vulnerable", "how_to_fix", "grounding_notes")
    )
    text = " ".join([text, *[str(step) for step in explanation.get("fix_steps", [])]])

    expected_file = str(finding.get("file") or "")
    expected_file_names = {expected_file, Path(expected_file).name} - {""}
    mentioned_files = set(re.findall(r"[\w./\\-]+\.java", text))
    unexpected_files = {
        mentioned_file
        for mentioned_file in mentioned_files
        if mentioned_file not in expected_file_names and Path(mentioned_file).name not in expected_file_names
    }
    if unexpected_files:
        notes.append(f"finding 위치와 다른 파일 언급: {', '.join(sorted(unexpected_files))}")

    expected_line = finding.get("line")
    if isinstance(expected_line, int):
        mentioned_lines = {
            int(match)
            for match in re.findall(r"(?:line\s+|라인\s*|)(\d{1,5})(?:\s*행)", text, flags=re.IGNORECASE)
        }
        mentioned_lines.update(
            int(match)
            for match in re.findall(r"line\s+(\d{1,5})", text, flags=re.IGNORECASE)
        )
        unexpected_lines = {line for line in mentioned_lines if line != expected_line}
        if unexpected_lines:
            notes.append(f"finding 위치와 다른 라인 언급: {', '.join(str(line) for line in sorted(unexpected_lines))}")

    return notes
