from __future__ import annotations

from src.app.services.llm_grounding import verify_finding_explanation
from src.app.services.llm_report_service import SecurityReportGenerator, _parse_json_object
from src.app.core.config import get_settings


def guideline_ref() -> dict:
    return {
        "id": "kr-sw-security-guide-2019-sql-injection",
        "source_title": "소프트웨어 보안약점 진단가이드",
        "source_version": "2019.6 개정",
        "source_file": "src/app/resources/guidelines/software-security-guide-2019/source.pdf",
        "category": "입력데이터 검증 및 표현",
        "item": "SQL 삽입",
        "page_start": 178,
        "page_end": 191,
        "detector_types": ["SQL_INJECTION"],
        "cwe": ["CWE-89"],
        "overview": "SQL 삽입 개요",
        "security_measures": "PreparedStatement를 사용한다.",
        "diagnosis": "Statement 객체를 통해 쿼리가 실행되는 부분을 확인한다.",
        "citations": [
            {
                "source": "소프트웨어 보안약점 진단가이드",
                "version": "2019.6 개정",
                "page_start": 178,
                "page_end": 191,
                "section": "입력데이터 검증 및 표현 - SQL 삽입",
            }
        ],
    }


def finding() -> dict:
    return {
        "id": "VULN-001",
        "type": "SQL_INJECTION",
        "file": "LoginService.java",
        "line": 12,
        "function": "authenticate",
        "evidence": "외부 입력이 SQL 실행 API로 전달됩니다.",
        "confidence_reason": "외부 입력 흐름이 확인되었습니다.",
        "call_chain": ["LoginService.authenticate", "stmt.executeQuery"],
        "guideline_refs": [guideline_ref()],
    }


def valid_explanation() -> dict:
    return {
        "why_vulnerable": "LoginService.java line 12에서 외부 입력이 SQL 실행 API로 전달됩니다.",
        "how_to_fix": "PreparedStatement를 사용하고 파라미터를 바인딩합니다.",
        "fix_steps": ["SQL 문자열 결합을 제거합니다.", "setString으로 값을 바인딩합니다."],
        "cited_guideline_ids": ["kr-sw-security-guide-2019-sql-injection"],
        "citations": guideline_ref()["citations"],
        "grounding_notes": None,
    }


def test_grounding_verifier_accepts_known_guideline_citation() -> None:
    result = verify_finding_explanation(finding=finding(), explanation=valid_explanation())

    assert result.passed is True
    assert result.notes == []


def test_grounding_verifier_rejects_unknown_guideline_id() -> None:
    explanation = valid_explanation()
    explanation["cited_guideline_ids"] = ["made-up-id"]

    result = verify_finding_explanation(finding=finding(), explanation=explanation)

    assert result.passed is False
    assert "made-up-id" in result.notes[0]


def test_grounding_verifier_rejects_invented_citation_page() -> None:
    explanation = valid_explanation()
    explanation["citations"] = [
        {
            "source": "소프트웨어 보안약점 진단가이드",
            "version": "2019.6 개정",
            "page_start": 999,
            "page_end": 999,
            "section": "입력데이터 검증 및 표현 - SQL 삽입",
        }
    ]

    result = verify_finding_explanation(finding=finding(), explanation=explanation)

    assert result.passed is False
    assert any("등록되지 않은 guideline citation" in note for note in result.notes)


def test_grounding_verifier_rejects_different_file_or_line_claim() -> None:
    explanation = valid_explanation()
    explanation["why_vulnerable"] = "OtherService.java line 99에서 SQL 삽입이 발생합니다."

    result = verify_finding_explanation(finding=finding(), explanation=explanation)

    assert result.passed is False
    assert any("다른 파일" in note for note in result.notes)
    assert any("다른 라인" in note for note in result.notes)


def test_parse_json_object_accepts_fenced_json() -> None:
    assert _parse_json_object('```json\n{"why_vulnerable": "ok"}\n```') == {"why_vulnerable": "ok"}


def test_finding_explanation_failure_does_not_remove_static_finding() -> None:
    class FailingExplanationGenerator(SecurityReportGenerator):
        def _generate_finding_explanation(self, finding: dict, llm: object) -> dict:  # type: ignore[override]
            raise RuntimeError("boom")

    result = {"analysis_result": {"vulnerabilities": [finding()]}}
    generator = FailingExplanationGenerator(get_settings())

    generator._attach_finding_explanations(result, llm=object())

    findings = result["analysis_result"]["vulnerabilities"]
    assert len(findings) == 1
    assert findings[0]["llm_explanation_status"] == "failed"
    assert findings[0]["llm_explanation"] is None
    assert "boom" in findings[0]["llm_explanation_error"]
