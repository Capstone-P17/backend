from __future__ import annotations

import json

from src.app.core.config import get_settings
from src.app.services.analysis_service import AnalysisService
from src.app.services.guidelines.repository import GuidelineRepository
from src.app.services.llm_report_service import (
    ContextBudgetExceededError,
    SecurityReportGenerator,
    _ensure_remediation_sections,
)
from src.app.services.result_store import AnalysisResultStore


def guideline_ref(ref_id: str = "kr-sw-security-guide-2019-sql-injection") -> dict:
    return {
        "id": ref_id,
        "source_title": "소프트웨어 보안약점 진단가이드",
        "source_version": "2019.6 개정",
        "source_file": "src/app/resources/guidelines/software-security-guide-2019/source.pdf",
        "category": "입력데이터 검증 및 표현",
        "item": "SQL 삽입",
        "page_start": 178,
        "page_end": 191,
        "detector_types": ["SQL_INJECTION"],
        "cwe": ["CWE-89"],
        "overview": "SQL 삽입 개요" * 200,
        "security_measures": "PreparedStatement를 사용한다." * 200,
        "diagnosis": "Statement 객체를 통해 쿼리가 실행되는 부분을 확인한다." * 200,
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


def finding(index: int, *, with_guideline: bool = True) -> dict:
    payload = {
        "id": f"VULN-{index:03d}",
        "type": "SQL_INJECTION" if index % 2 == 0 else "XSS",
        "severity": "HIGH" if index % 3 == 0 else "MEDIUM",
        "file": f"src/File{index}.java",
        "line": index + 1,
        "function": "run",
        "description": "사용자 입력이 위험한 API로 전달됩니다." * 20,
        "evidence": "외부 입력이 SQL 실행 API로 전달됩니다." * 100,
        "recommendation": "PreparedStatement를 사용하세요." * 50,
        "call_chain": [f"A{index}.run", "B.exec", "C.sink"],
        "confidence": "HIGH",
        "confidence_reason": "외부 입력 흐름이 확인되었습니다." * 50,
        "guideline_grounding_status": "matched" if with_guideline else "missing",
        "analysis_status": "confirmed" if with_guideline else "needs_review",
        "guideline_refs": [guideline_ref()] if with_guideline else [],
    }
    return payload


def result_with_findings(total: int) -> dict:
    return {
        "analysis_result": {
            "repository": "repo",
            "target_path": "src",
            "language": "java",
            "files_analyzed": total,
            "summary": {"total_vulnerabilities": total},
            "call_graph": {f"A{i}.run": ["B.exec"] for i in range(total)},
            "vulnerabilities": [finding(i) for i in range(total)],
        }
    }


def test_final_report_payload_deduplicates_guidelines_and_excludes_raw_guideline_text() -> None:
    settings = get_settings().model_copy(update={"llm_report_max_detailed_findings": 5})
    payload = SecurityReportGenerator(settings)._build_payload(result_with_findings(12))

    assert payload["finding_selection"]["total_static_findings"] == 12
    assert len(payload["vulnerabilities"]) == 5
    assert list(payload["guideline_catalog"]) == ["kr-sw-security-guide-2019-sql-injection"]

    serialized = json.dumps(payload, ensure_ascii=False)
    assert "SQL 삽입 개요SQL 삽입 개요" not in serialized
    assert "PreparedStatement를 사용한다.PreparedStatement를 사용한다." not in serialized
    assert "Statement 객체를 통해 쿼리가 실행되는 부분" not in serialized
    assert all("guideline_refs" not in item for item in payload["vulnerabilities"])
    assert any(item["guideline_ref_ids"] == ["kr-sw-security-guide-2019-sql-injection"] for item in payload["vulnerabilities"])
    assert all(
        item["guideline_ref_ids"] in ([], ["kr-sw-security-guide-2019-sql-injection"])
        for item in payload["vulnerabilities"]
    )


def test_guideline_catalog_deduplicates_allowed_citations() -> None:
    duplicate_ref = guideline_ref()
    duplicate_ref["citations"] = [*duplicate_ref["citations"], *duplicate_ref["citations"]]
    result = result_with_findings(2)
    result["analysis_result"]["vulnerabilities"][0]["guideline_refs"] = [duplicate_ref]
    result["analysis_result"]["vulnerabilities"][1]["guideline_refs"] = [duplicate_ref]

    payload = SecurityReportGenerator(get_settings())._build_payload(result)
    catalog_entry = payload["guideline_catalog"]["kr-sw-security-guide-2019-sql-injection"]

    assert len(catalog_entry["allowed_citations"]) == 1


def test_finding_detail_payload_filters_stale_category_wide_guidelines() -> None:
    repository = GuidelineRepository.load()
    stale_category_refs = [
        reference.to_finding_payload()
        for reference in repository.references
        if reference.category == "입력데이터 검증 및 표현"
    ]
    selected = finding(1)
    selected.update(
        {
            "type": "SQL_INJECTION",
            "cwe": "CWE-89",
            "guide_item": "SQL 삽입",
            "guide_category": "입력데이터 검증 및 표현",
            "guideline_refs": stale_category_refs,
        }
    )

    payload = SecurityReportGenerator(get_settings())._build_finding_detail_payload(
        finding=selected,
        analysis={"repository": "repo", "language": "java", "vulnerabilities": [selected]},
    )

    refs = payload["finding"]["guideline_refs"]
    assert [ref["section"] for ref in refs] == ["입력데이터 검증 및 표현 - SQL 삽입"]


def test_finding_detail_payload_compacts_before_budget_failure() -> None:
    settings = get_settings().model_copy(update={"llm_finding_detail_payload_max_chars": 9_000})
    selected = finding(2)
    selected.update(
        {
            "code_snippet": "String sql = request.getParameter(\"q\");\n" * 120,
            "safe_example": "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\n"
            * 80,
            "call_chain_details": [
                {
                    "label": f"step-{index}",
                    "file": "src/VeryLongPath.java",
                    "function": "run",
                    "note": "long note " * 80,
                }
                for index in range(12)
            ],
            "llm_explanation": {
                "why_vulnerable": "외부 입력이 SQL 문자열에 결합됩니다." * 120,
                "how_to_fix": "파라미터 바인딩을 사용합니다." * 120,
                "fix_steps": ["PreparedStatement 적용" * 40 for _ in range(8)],
                "cited_guideline_ids": ["kr-sw-security-guide-2019-sql-injection"],
                "citations": guideline_ref()["citations"],
            },
        }
    )
    generator = SecurityReportGenerator(settings)
    payload = generator._build_finding_detail_payload(
        finding=selected,
        analysis={"repository": "repo", "language": "java", "vulnerabilities": [selected]},
    )

    dumped = generator._dump_finding_detail_payload_with_budget(payload)

    assert len(dumped) <= settings.llm_finding_detail_payload_max_chars
    assert "budget_compaction" in dumped


def test_generated_finding_markdown_is_backfilled_with_static_remediation() -> None:
    selected = finding(2)
    selected["safe_example"] = 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");'
    selected["code_snippet"] = ' 10 | String sql = "SELECT * FROM users WHERE id = " + userId;\n> 11 | stmt.executeQuery(sql);'

    markdown = _ensure_remediation_sections("# 요약\nLLM이 보수적으로 요약만 작성했습니다.", selected)

    assert "# 수정 방법" in markdown
    assert "PreparedStatement를 사용하세요." in markdown
    assert "# 수정 예시" in markdown
    assert "PreparedStatement ps = conn.prepareStatement" in markdown


def test_finding_explanation_input_uses_compact_guideline_brief_limits() -> None:
    settings = get_settings().model_copy(
        update={
            "llm_guideline_overview_max_chars": 30,
            "llm_guideline_security_measures_max_chars": 40,
            "llm_guideline_diagnosis_max_chars": 50,
            "llm_finding_evidence_max_chars": 35,
        }
    )
    payload = SecurityReportGenerator(settings)._build_finding_explanation_input(finding(2))
    ref = payload["guideline_refs"][0]

    assert set(ref) == {
        "id",
        "source",
        "version",
        "section",
        "pages",
        "why_vulnerable",
        "diagnosis_rules",
        "fix_rules",
        "citations",
    }
    assert len(ref["why_vulnerable"]) <= 31
    assert len(ref["fix_rules"]) <= 41
    assert len(ref["diagnosis_rules"]) <= 51
    assert len(payload["evidence"]) <= 36
    assert "overview" not in ref
    assert "security_measures" not in ref
    assert "diagnosis" not in ref


def test_report_payload_budget_raises_after_compaction_without_deleting_findings() -> None:
    settings = get_settings().model_copy(
        update={"llm_report_payload_max_chars": 200, "llm_report_max_detailed_findings": 10}
    )
    generator = SecurityReportGenerator(settings)
    result = result_with_findings(20)

    try:
        generator._dump_payload_with_budget(generator._build_payload(result))
    except ContextBudgetExceededError as exc:
        assert "budget" in str(exc)

    assert len(result["analysis_result"]["vulnerabilities"]) == 20


def test_context_budget_error_marks_llm_report_skipped_and_keeps_static_findings() -> None:
    class FakeAnalyzerService:
        def analyze(self, target_path: str, repository: str = "") -> dict:
            return result_with_findings(1)

    class EmptyGuidelineRepository:
        def find_for_finding(self, finding: dict) -> list:
            return []

    class BudgetFailingReportGenerator:
        is_available = True

        def generate(self, *, result: dict, target_path: str = "", repository: str = "", instructions: str = "") -> str:
            raise ContextBudgetExceededError("too large")

    settings = get_settings().model_copy(update={"openai_api_key": "test-key", "openai_model": "test-model"})
    service = AnalysisService(
        settings=settings,
        analyzer_service=FakeAnalyzerService(),  # type: ignore[arg-type]
        result_store=AnalysisResultStore(),
        report_generator=BudgetFailingReportGenerator(),  # type: ignore[arg-type]
        guideline_repository=EmptyGuidelineRepository(),  # type: ignore[arg-type]
    )

    response = service.analyze_uploaded_file("Unsafe.java", b"public class Unsafe {}", user_id=1)
    analysis = response["analysis_result"]

    assert len(analysis["vulnerabilities"]) == 1
    assert analysis["llm_report"] is None
    assert analysis["llm_report_status"] == "skipped_context_budget_exceeded"
    assert analysis["llm_report_error"] == "too large"
