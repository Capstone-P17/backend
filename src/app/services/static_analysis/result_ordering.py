from __future__ import annotations

import re
from copy import deepcopy
from typing import Any


TYPE_PRIORITY = {
    "COMMAND_INJECTION": 0,
    "SQL_INJECTION": 1,
    "PATH_TRAVERSAL": 2,
    "DANGEROUS_FILE_UPLOAD": 3,
    "XSS": 4,
    "HARDCODED_SECRET": 5,
    "WEAK_HASH": 6,
    "INSECURE_RANDOM": 7,
}

CONFIDENCE_PRIORITY = {
    "HIGH": 0,
    "MEDIUM": 1,
    "LOW": 2,
}

_MISSING_LINE = 10**9


def prioritize_findings(findings: Any) -> list[dict[str, Any]]:
    """Return findings deduplicated, risk-prioritized, and renumbered for display."""

    if not isinstance(findings, list):
        return []

    merged_by_key: dict[tuple[str, str, int | None, str, str, str], dict[str, Any]] = {}
    for raw_finding in findings:
        if not isinstance(raw_finding, dict):
            continue
        finding = deepcopy(raw_finding)
        key = _dedup_key(finding)
        existing = merged_by_key.get(key)
        if existing is None:
            finding["duplicate_count"] = max(_safe_int(finding.get("duplicate_count"), default=1), 1)
            finding["related_finding_ids"] = _unique_strings(finding.get("related_finding_ids"))
            merged_by_key[key] = finding
            continue
        _merge_duplicate(existing, finding)

    prioritized = sort_findings(list(merged_by_key.values()))
    for index, finding in enumerate(prioritized, start=1):
        previous_id = str(finding.get("id") or "").strip()
        if (
            _safe_int(finding.get("duplicate_count"), default=1) > 1
            and previous_id
            and previous_id != f"VULN-{index:03d}"
        ):
            related_ids = _unique_strings([*finding.get("related_finding_ids", []), previous_id])
            finding["related_finding_ids"] = related_ids
        finding["id"] = f"VULN-{index:03d}"
    return prioritized


def sort_findings(findings: Any) -> list[dict[str, Any]]:
    if not isinstance(findings, list):
        return []
    return sorted([finding for finding in findings if isinstance(finding, dict)], key=finding_sort_key)


def finding_sort_key(finding: dict[str, Any]) -> tuple[int, int, str, int, str, str]:
    finding_type = str(finding.get("type") or "").upper()
    confidence = str(finding.get("confidence") or "").upper()
    return (
        TYPE_PRIORITY.get(finding_type, 99),
        CONFIDENCE_PRIORITY.get(confidence, 9),
        str(finding.get("file") or ""),
        _line_number(finding.get("line")),
        str(finding.get("function") or ""),
        str(finding.get("id") or ""),
    )


def _dedup_key(finding: dict[str, Any]) -> tuple[str, str, int | None, str, str, str]:
    line = finding.get("line")
    return (
        str(finding.get("type") or "").upper(),
        str(finding.get("file") or ""),
        line if isinstance(line, int) else None,
        str(finding.get("function") or ""),
        _normalized_text(finding.get("code_snippet")),
        _sink_label(finding),
    )


def _merge_duplicate(base: dict[str, Any], duplicate: dict[str, Any]) -> None:
    base["duplicate_count"] = _safe_int(base.get("duplicate_count"), default=1) + _safe_int(
        duplicate.get("duplicate_count"),
        default=1,
    )

    duplicate_ids = _unique_strings(
        [
            *base.get("related_finding_ids", []),
            duplicate.get("id"),
            *duplicate.get("related_finding_ids", []),
        ]
    )
    base["related_finding_ids"] = duplicate_ids

    _merge_unique_list_field(base, duplicate, "call_chain")
    _merge_unique_dict_list_field(base, duplicate, "call_chain_details")
    _merge_unique_dict_list_field(base, duplicate, "guideline_refs", identity_fields=("id", "category", "item"))

    for field, label in (
        ("evidence", "추가 근거"),
        ("confidence_reason", "추가 신뢰도 근거"),
        ("description", "추가 설명"),
        ("recommendation", "추가 수정 방향"),
    ):
        _merge_text_field(base, duplicate, field, label)

    if _confidence_rank(duplicate.get("confidence")) < _confidence_rank(base.get("confidence")):
        base["confidence"] = duplicate.get("confidence")
        if duplicate.get("confidence_reason"):
            base["confidence_reason"] = duplicate.get("confidence_reason")

    if not isinstance(base.get("line"), int) and isinstance(duplicate.get("line"), int):
        base["line"] = duplicate["line"]


def _merge_text_field(base: dict[str, Any], duplicate: dict[str, Any], field: str, label: str) -> None:
    base_text = str(base.get(field) or "").strip()
    duplicate_text = str(duplicate.get(field) or "").strip()
    if not duplicate_text or duplicate_text == base_text or duplicate_text in base_text:
        return
    if not base_text:
        base[field] = duplicate_text
        return
    base[field] = f"{base_text}\n\n{label}: {duplicate_text}"


def _merge_unique_list_field(base: dict[str, Any], duplicate: dict[str, Any], field: str) -> None:
    base[field] = _unique_strings([*base.get(field, []), *duplicate.get(field, [])])


def _merge_unique_dict_list_field(
    base: dict[str, Any],
    duplicate: dict[str, Any],
    field: str,
    *,
    identity_fields: tuple[str, ...] = ("label", "kind", "file", "line", "function"),
) -> None:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for item in [*base.get(field, []), *duplicate.get(field, [])]:
        if not isinstance(item, dict):
            continue
        key = tuple(item.get(identity_field) for identity_field in identity_fields)
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    base[field] = merged


def _sink_label(finding: dict[str, Any]) -> str:
    call_chain = finding.get("call_chain")
    if isinstance(call_chain, list) and call_chain:
        return _normalized_text(call_chain[-1])
    call_chain_details = finding.get("call_chain_details")
    if isinstance(call_chain_details, list):
        for detail in reversed(call_chain_details):
            if isinstance(detail, dict) and str(detail.get("kind") or "") == "sink":
                return _normalized_text(detail.get("label"))
    return ""


def _normalized_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _line_number(value: Any) -> int:
    return value if isinstance(value, int) else _MISSING_LINE


def _confidence_rank(value: Any) -> int:
    return CONFIDENCE_PRIORITY.get(str(value or "").upper(), 9)


def _safe_int(value: Any, *, default: int) -> int:
    return value if isinstance(value, int) else default


def _unique_strings(values: Any) -> list[str]:
    unique: list[str] = []
    seen: set[str] = set()
    if not isinstance(values, list):
        return unique
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        unique.append(text)
    return unique
