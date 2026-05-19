from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.app.core.config import PROJECT_ROOT
from src.app.schemas.analysis import VulnerabilityFinding
from src.app.services.analyzer_service import AnalyzerService

EXPECTED_TYPES = {
    "SQL_INJECTION",
    "XSS",
    "HARDCODED_SECRET",
    "PATH_TRAVERSAL",
    "COMMAND_INJECTION",
    "INSECURE_RANDOM",
    "WEAK_HASH",
}


def test_sample_analysis_detects_expected_java_findings() -> None:
    result = AnalyzerService(PROJECT_ROOT).analyze("src/analyzer/test_samples")
    analysis = result["analysis_result"]
    assert analysis["files_analyzed"] == 7
    assert analysis["summary"]["total_vulnerabilities"] == 23
    assert {finding["type"] for finding in analysis["vulnerabilities"]} == EXPECTED_TYPES
    for finding in analysis["vulnerabilities"]:
        assert finding["description"]
        assert finding["recommendation"]
        assert finding["cwe"]
        assert finding["guide_source"] == "행정안전부 「소프트웨어 보안약점 진단가이드(2019.6. 개정)」"
        assert finding["guide_category"]
        assert finding["guide_item"]
        assert finding["confidence"] in {"HIGH", "MEDIUM", "LOW"}


def test_vulnerability_schema_requires_enriched_fields() -> None:
    base = {
        "id": "VULN-001",
        "type": "SQL_INJECTION",
        "severity": "HIGH",
        "file": "UserDAO.java",
        "line": 10,
        "function": "findUser",
        "code_snippet": "stmt.executeQuery(sql)",
        "call_chain": [],
        "description": "사용자 입력이 SQL에 직접 결합됩니다.",
        "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    }

    for required_field in (
        "cwe",
        "guide_source",
        "guide_category",
        "guide_item",
        "recommendation",
        "safe_example",
        "confidence",
    ):
        payload = {
            **base,
            "cwe": "CWE-89",
            "guide_source": "행정안전부 「소프트웨어 보안약점 진단가이드(2019.6. 개정)」",
            "guide_category": "입력데이터 검증 및 표현",
            "guide_item": "SQL 삽입",
            "recommendation": "PreparedStatement를 사용하세요.",
            "safe_example": "PreparedStatement ps = conn.prepareStatement(sql);",
            "confidence": "HIGH",
        }
        payload.pop(required_field)
        with pytest.raises(ValidationError):
            VulnerabilityFinding.model_validate(payload)
