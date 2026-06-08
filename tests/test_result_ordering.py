from __future__ import annotations

from src.app.services.static_analysis.result_ordering import prioritize_findings


def _finding(
    finding_id: str,
    finding_type: str,
    *,
    file: str = "src/UserController.java",
    line: int = 10,
    function: str = "handle",
    code: str = "sink(value);",
    sink: str = "sink",
    confidence: str = "HIGH",
    evidence: str = "기본 근거",
) -> dict[str, object]:
    return {
        "id": finding_id,
        "type": finding_type,
        "file": file,
        "line": line,
        "function": function,
        "code_snippet": code,
        "call_chain": ["source", sink],
        "evidence": evidence,
        "confidence": confidence,
        "description": "설명",
        "recommendation": "수정 방향",
        "safe_example": "safe();",
        "guide_source": "행정안전부 「소프트웨어 보안약점 진단가이드(2019.6. 개정)」",
        "guide_category": "입력데이터 검증 및 표현",
        "guide_item": finding_type,
    }


def test_prioritize_findings_sorts_by_risk_confidence_and_location() -> None:
    findings = [
        _finding("old-weak", "WEAK_HASH", line=1),
        _finding("old-sql-medium", "SQL_INJECTION", line=20, confidence="MEDIUM"),
        _finding("old-command", "COMMAND_INJECTION", line=99),
        _finding("old-sql-high", "SQL_INJECTION", line=5),
        _finding("old-xss", "XSS", line=3),
    ]

    ordered = prioritize_findings(findings)

    assert [(finding["id"], finding["type"], finding["line"]) for finding in ordered] == [
        ("VULN-001", "COMMAND_INJECTION", 99),
        ("VULN-002", "SQL_INJECTION", 5),
        ("VULN-003", "SQL_INJECTION", 20),
        ("VULN-004", "XSS", 3),
        ("VULN-005", "WEAK_HASH", 1),
    ]


def test_prioritize_findings_merges_duplicate_location_code_and_sink() -> None:
    findings = [
        _finding("VULN-002", "SQL_INJECTION", evidence="문자열 결합 SQL 실행"),
        _finding("VULN-009", "SQL_INJECTION", evidence="executeQuery sink 도달"),
    ]

    ordered = prioritize_findings(findings)

    assert len(ordered) == 1
    assert ordered[0]["id"] == "VULN-001"
    assert ordered[0]["duplicate_count"] == 2
    assert ordered[0]["related_finding_ids"] == ["VULN-009", "VULN-002"]
    assert "문자열 결합 SQL 실행" in str(ordered[0]["evidence"])
    assert "executeQuery sink 도달" in str(ordered[0]["evidence"])


def test_prioritize_findings_keeps_same_line_different_sink_separate() -> None:
    findings = [
        _finding("VULN-002", "SQL_INJECTION", sink="stmt.executeQuery"),
        _finding("VULN-009", "SQL_INJECTION", sink="stmt.executeUpdate"),
    ]

    ordered = prioritize_findings(findings)

    assert len(ordered) == 2
    assert [finding["id"] for finding in ordered] == ["VULN-001", "VULN-002"]
