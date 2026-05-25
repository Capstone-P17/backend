from __future__ import annotations

from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from src.app.core.config import get_settings
from src.app.services.analysis_service import AnalysisService, InvalidRepositoryArchiveError, UploadTooLargeError
from src.app.services.analyzer_service import AnalyzerService
from src.app.services.llm_report_service import SecurityReportGenerator
from src.app.services.result_store import AnalysisResultStore


def java_bytes() -> bytes:
    return b"public class Safe { public void ok() { System.out.println(\"ok\"); } }"


def zip_bytes() -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("repo/Safe.java", java_bytes())
    return buffer.getvalue()


def oversized_zip_bytes() -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("repo/Oversized.java", b"a" * 1024)
    return buffer.getvalue()


def assert_analysis_response(response: dict) -> None:
    assert response["analysis_id"]
    assert response["analysis_result"]["language"] == "java"
    assert response["analysis_result"]["files_analyzed"] >= 1
    assert response["analysis_result"]["llm_report_status"] == "unavailable"
    assert response["analysis_result"]["llm_report"] is None


def test_uploaded_file_returns_analysis_id_envelope(analysis_service: AnalysisService) -> None:
    assert_analysis_response(analysis_service.analyze_uploaded_file("Safe.java", java_bytes(), user_id=1))


def test_uploaded_repository_returns_analysis_id_envelope(analysis_service: AnalysisService) -> None:
    assert_analysis_response(analysis_service.analyze_uploaded_repository("repo.zip", zip_bytes(), user_id=1))


def test_uploaded_file_rejects_configured_size_limit() -> None:
    settings = get_settings().model_copy(update={"max_upload_bytes": 8})
    service = AnalysisService(
        settings=settings,
        analyzer_service=AnalyzerService(settings.workspace_root),
        result_store=AnalysisResultStore(),
    )

    with pytest.raises(UploadTooLargeError):
        service.analyze_uploaded_file("Safe.java", java_bytes(), user_id=1)


def test_uploaded_repository_rejects_uncompressed_zip_limit() -> None:
    settings = get_settings().model_copy(update={"max_upload_bytes": 512})
    service = AnalysisService(
        settings=settings,
        analyzer_service=AnalyzerService(settings.workspace_root),
        result_store=AnalysisResultStore(),
    )

    with pytest.raises(InvalidRepositoryArchiveError):
        service.analyze_uploaded_repository("repo.zip", oversized_zip_bytes(), user_id=1)


def test_github_repository_returns_analysis_id_envelope_without_network(monkeypatch, analysis_service: AnalysisService) -> None:
    monkeypatch.setattr(analysis_service, "_download_github_archive", lambda owner, repo: (zip_bytes(), "main"))
    assert_analysis_response(analysis_service.analyze_github_repository("https://github.com/acme/repo", user_id=1))


def test_analysis_result_includes_generated_llm_report_when_available() -> None:
    class FakeReportGenerator:
        is_available = True

        def generate(self, *, result: dict, target_path: str = "", repository: str = "", instructions: str = "") -> str:
            assert result["analysis_result"]["files_analyzed"] == 1
            assert target_path
            assert instructions == ""
            return "LLM 리포트 본문"

    settings = get_settings().model_copy(update={"openai_api_key": "test-key", "openai_model": "test-model"})
    result_store = AnalysisResultStore()
    service = AnalysisService(
        settings=settings,
        analyzer_service=AnalyzerService(settings.workspace_root),
        result_store=result_store,
        report_generator=FakeReportGenerator(),  # type: ignore[arg-type]
    )

    response = service.analyze_uploaded_file("Safe.java", java_bytes(), user_id=1)
    analysis = response["analysis_result"]

    assert analysis["llm_report_status"] == "generated"
    assert analysis["llm_report"] == "LLM 리포트 본문"
    assert analysis["llm_report_available"] is True
    assert analysis["llm_model"] == "test-model"
    assert result_store.get(response["analysis_id"], user_id=1)["analysis_result"]["llm_report"] == "LLM 리포트 본문"


def test_analysis_result_attaches_finding_explanations_before_llm_report() -> None:
    class FakeAnalyzerService:
        def analyze(self, target_path: str, repository: str = "") -> dict:
            return {
                "analysis_result": {
                    "repository": repository,
                    "target_path": target_path,
                    "language": "java",
                    "files_analyzed": 1,
                    "analyzed_at": "2026-01-01T00:00:00",
                    "call_graph": {},
                    "summary": {
                        "total_vulnerabilities": 1,
                        "by_type": {"SQL_INJECTION": 1},
                        "by_guide_category": {"입력데이터 검증 및 표현": 1},
                        "by_severity": {"HIGH": 1},
                        "score": {"overall": 90, "by_file": {"Unsafe.java": 90}},
                    },
                    "vulnerabilities": [
                        {
                            "id": "VULN-001",
                            "type": "SQL_INJECTION",
                            "severity": "HIGH",
                            "cwe": "CWE-89",
                            "guide_source": "행정안전부 「소프트웨어 보안약점 진단가이드(2019.6. 개정)」",
                            "guide_category": "입력데이터 검증 및 표현",
                            "guide_item": "SQL 삽입",
                            "file": "Unsafe.java",
                            "line": 1,
                            "function": "run",
                            "code_snippet": "stmt.executeQuery(sql)",
                            "call_chain": ["Unsafe.run", "stmt.executeQuery"],
                            "evidence": "외부 입력이 SQL 실행 API로 전달됩니다.",
                            "description": "SQL 삽입",
                            "recommendation": "PreparedStatement를 사용하세요.",
                            "safe_example": "PreparedStatement ps = conn.prepareStatement(sql);",
                            "confidence": "HIGH",
                            "confidence_reason": "외부 입력 흐름이 확인되었습니다.",
                        }
                    ],
                }
            }

    class FakeReportGenerator:
        is_available = True

        def attach_finding_explanations(self, result: dict) -> None:
            finding = result["analysis_result"]["vulnerabilities"][0]
            assert finding["guideline_refs"]
            finding["llm_explanation_status"] = "generated"
            finding["llm_explanation"] = {
                "why_vulnerable": "SQL 문자열에 외부 입력이 포함됩니다.",
                "how_to_fix": "PreparedStatement 바인딩을 사용합니다.",
                "fix_steps": ["SQL을 ? placeholder로 바꿉니다."],
                "cited_guideline_ids": [finding["guideline_refs"][0]["id"]],
                "citations": [],
                "grounding_notes": None,
            }
            finding["llm_explanation_error"] = None

        def generate(self, *, result: dict, target_path: str = "", repository: str = "", instructions: str = "") -> str:
            assert result["analysis_result"]["vulnerabilities"][0]["llm_explanation_status"] == "generated"
            return "LLM 리포트 본문"

    settings = get_settings().model_copy(update={"openai_api_key": "test-key", "openai_model": "test-model"})
    service = AnalysisService(
        settings=settings,
        analyzer_service=FakeAnalyzerService(),  # type: ignore[arg-type]
        result_store=AnalysisResultStore(),
        report_generator=FakeReportGenerator(),  # type: ignore[arg-type]
    )

    response = service.analyze_uploaded_file("Unsafe.java", java_bytes(), user_id=1)
    finding = response["analysis_result"]["vulnerabilities"][0]

    assert finding["llm_explanation_status"] == "generated"
    assert finding["llm_explanation"]["why_vulnerable"] == "SQL 문자열에 외부 입력이 포함됩니다."
    assert finding["llm_explanation"]["how_to_fix"] == "PreparedStatement 바인딩을 사용합니다."
    assert finding["llm_explanation"]["fix_steps"] == ["SQL을 ? placeholder로 바꿉니다."]


def test_analysis_result_attaches_guideline_references_before_storage() -> None:
    class FakeAnalyzerService:
        def analyze(self, target_path: str, repository: str = "") -> dict:
            return {
                "analysis_result": {
                    "repository": repository,
                    "target_path": target_path,
                    "language": "java",
                    "files_analyzed": 1,
                    "analyzed_at": "2026-01-01T00:00:00",
                    "call_graph": {},
                    "summary": {
                        "total_vulnerabilities": 1,
                        "by_type": {"SQL_INJECTION": 1},
                        "by_guide_category": {"입력데이터 검증 및 표현": 1},
                        "by_severity": {"HIGH": 1},
                        "score": {"overall": 90, "by_file": {"Unsafe.java": 90}},
                    },
                    "vulnerabilities": [
                        {
                            "id": "VULN-001",
                            "type": "SQL_INJECTION",
                            "severity": "HIGH",
                            "cwe": "CWE-89",
                            "guide_source": "행정안전부 「소프트웨어 보안약점 진단가이드(2019.6. 개정)」",
                            "guide_category": "입력데이터 검증 및 표현",
                            "guide_item": "SQL 삽입",
                            "file": "Unsafe.java",
                            "line": 1,
                            "function": "run",
                            "code_snippet": "stmt.executeQuery(sql)",
                            "call_chain": ["Unsafe.run", "stmt.executeQuery"],
                            "evidence": "외부 입력이 SQL 실행 API로 전달됩니다.",
                            "description": "SQL 삽입",
                            "recommendation": "PreparedStatement를 사용하세요.",
                            "safe_example": "PreparedStatement ps = conn.prepareStatement(sql);",
                            "confidence": "HIGH",
                            "confidence_reason": "외부 입력 흐름이 확인되었습니다.",
                        }
                    ],
                }
            }

    settings = get_settings()
    result_store = AnalysisResultStore()
    service = AnalysisService(
        settings=settings,
        analyzer_service=FakeAnalyzerService(),  # type: ignore[arg-type]
        result_store=result_store,
    )

    response = service.analyze_uploaded_file("Unsafe.java", java_bytes(), user_id=1)
    finding = response["analysis_result"]["vulnerabilities"][0]

    assert finding["guideline_refs"]
    assert finding["guideline_refs"][0]["item"] == "SQL 삽입"
    assert finding["guideline_refs"][0]["page_start"] == 178
    assert "PreparedStatement" in finding["guideline_refs"][0]["security_measures"]
    assert finding["guideline_grounding_status"] == "matched"
    assert finding["analysis_status"] == "confirmed"


def test_analysis_result_keeps_unmapped_findings_as_needs_review() -> None:
    class FakeAnalyzerService:
        def analyze(self, target_path: str, repository: str = "") -> dict:
            return {
                "analysis_result": {
                    "repository": repository,
                    "target_path": target_path,
                    "language": "java",
                    "files_analyzed": 1,
                    "analyzed_at": "2026-01-01T00:00:00",
                    "call_graph": {},
                    "summary": {
                        "total_vulnerabilities": 1,
                        "by_type": {"UNKNOWN_STATIC_FINDING": 1},
                        "by_guide_category": {},
                        "by_severity": {"LOW": 1},
                        "score": {"overall": 95, "by_file": {"Unknown.java": 95}},
                    },
                    "vulnerabilities": [
                        {
                            "id": "VULN-999",
                            "type": "UNKNOWN_STATIC_FINDING",
                            "severity": "LOW",
                            "cwe": "CWE-000",
                            "guide_source": "",
                            "guide_category": "",
                            "guide_item": "",
                            "file": "Unknown.java",
                            "line": 1,
                            "function": "run",
                            "code_snippet": "unknown();",
                            "call_chain": [],
                            "evidence": "정적 분석 evidence는 존재합니다.",
                            "description": "미매핑 정적 분석 finding",
                            "recommendation": "검토가 필요합니다.",
                            "safe_example": "",
                            "confidence": "LOW",
                            "confidence_reason": "테스트용 finding입니다.",
                        }
                    ],
                }
            }

    settings = get_settings()
    service = AnalysisService(
        settings=settings,
        analyzer_service=FakeAnalyzerService(),  # type: ignore[arg-type]
        result_store=AnalysisResultStore(),
    )

    response = service.analyze_uploaded_file("Unknown.java", java_bytes(), user_id=1)
    findings = response["analysis_result"]["vulnerabilities"]

    assert len(findings) == 1
    assert findings[0]["guideline_refs"] == []
    assert findings[0]["guideline_grounding_status"] == "missing"
    assert findings[0]["analysis_status"] == "needs_review"


def test_llm_report_payload_uses_report_friendly_vulnerability_fields() -> None:
    settings = get_settings().model_copy(update={"analysis_max_findings_in_prompt": 5})
    generator = SecurityReportGenerator(settings)

    payload = generator._build_payload(
        {
            "analysis_result": {
                "repository": "repo",
                "target_path": "src",
                "language": "java",
                "files_analyzed": 1,
                "summary": {"total_vulnerabilities": 1},
                "call_graph": {"A.run": ["B.exec"]},
                "vulnerabilities": [
                    {
                        "type": "SQL_INJECTION",
                        "severity": "HIGH",
                        "file": "src/LoginService.java",
                        "line": 12,
                        "function": "authenticate",
                        "description": "사용자 입력이 그대로 SQL에 연결됩니다.",
                        "evidence": "외부 입력이 SQL 실행 API로 전달됩니다.",
                        "recommendation": "PreparedStatement를 사용하세요.",
                        "call_chain": ["AuthController.login", "LoginService.authenticate"],
                        "confidence": "HIGH",
                        "confidence_reason": "외부 입력 흐름이 확인되었습니다.",
                        "guideline_refs": [
                            {
                                "id": "kr-sw-security-guide-2019-sql-injection",
                                "source_title": "소프트웨어 보안약점 진단가이드",
                                "source_version": "2019.6 개정",
                                "category": "입력데이터 검증 및 표현",
                                "item": "SQL 삽입",
                                "page_start": 178,
                                "page_end": 191,
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
                        ],
                        "code_snippet": "String query = ...",
                    }
                ],
            }
        }
    )

    assert payload["finding_selection"]["total_static_findings"] == 1
    assert payload["vulnerabilities"][0] == {
        "id": None,
        "type": "SQL_INJECTION",
        "severity": "HIGH",
        "file": "src/LoginService.java",
        "line": 12,
        "function": "authenticate",
        "description": "사용자 입력이 그대로 SQL에 연결됩니다.",
        "evidence": "외부 입력이 SQL 실행 API로 전달됩니다.",
        "recommendation": "PreparedStatement를 사용하세요.",
        "call_chain": ["AuthController.login", "LoginService.authenticate"],
        "confidence": "HIGH",
        "confidence_reason": "외부 입력 흐름이 확인되었습니다.",
        "guideline_grounding_status": None,
        "analysis_status": None,
        "llm_explanation_status": None,
        "llm_explanation": None,
        "llm_explanation_error": None,
        "guideline_ref_ids": ["kr-sw-security-guide-2019-sql-injection"],
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
    assert "guideline_refs" not in payload["vulnerabilities"][0]
    assert payload["guideline_catalog"] == {
        "kr-sw-security-guide-2019-sql-injection": {
            "id": "kr-sw-security-guide-2019-sql-injection",
            "source": "소프트웨어 보안약점 진단가이드",
            "version": "2019.6 개정",
            "section": "입력데이터 검증 및 표현 - SQL 삽입",
            "pages": [178, 191],
            "detector_types": [],
            "cwe": [],
            "allowed_citations": [
                {
                    "source": "소프트웨어 보안약점 진단가이드",
                    "version": "2019.6 개정",
                    "page_start": 178,
                    "page_end": 191,
                    "section": "입력데이터 검증 및 표현 - SQL 삽입",
                }
            ],
        }
    }
    assert "overview" not in payload["guideline_catalog"]["kr-sw-security-guide-2019-sql-injection"]
