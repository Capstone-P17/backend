from __future__ import annotations

from io import BytesIO
from zipfile import ZipFile

from src.app.core.config import get_settings
from src.app.services.analysis_service import AnalysisService
from src.app.services.analyzer_service import AnalyzerService
from src.app.services.result_store import AnalysisResultStore


def java_bytes() -> bytes:
    return b"public class Safe { public void ok() { System.out.println(\"ok\"); } }"


def zip_bytes() -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("repo/Safe.java", java_bytes())
    return buffer.getvalue()


def assert_analysis_response(response: dict) -> None:
    assert response["analysis_id"]
    assert response["analysis_result"]["language"] == "java"
    assert response["analysis_result"]["files_analyzed"] >= 1
    assert response["analysis_result"]["llm_report_status"] == "unavailable"
    assert response["analysis_result"]["llm_report"] is None


def test_uploaded_file_returns_analysis_id_envelope(analysis_service: AnalysisService) -> None:
    assert_analysis_response(analysis_service.analyze_uploaded_file("Safe.java", java_bytes()))


def test_uploaded_repository_returns_analysis_id_envelope(analysis_service: AnalysisService) -> None:
    assert_analysis_response(analysis_service.analyze_uploaded_repository("repo.zip", zip_bytes()))


def test_github_repository_returns_analysis_id_envelope_without_network(monkeypatch, analysis_service: AnalysisService) -> None:
    monkeypatch.setattr(analysis_service, "_download_github_archive", lambda owner, repo: (zip_bytes(), "main"))
    assert_analysis_response(analysis_service.analyze_github_repository("https://github.com/acme/repo"))


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

    response = service.analyze_uploaded_file("Safe.java", java_bytes())
    analysis = response["analysis_result"]

    assert analysis["llm_report_status"] == "generated"
    assert analysis["llm_report"] == "LLM 리포트 본문"
    assert analysis["llm_report_available"] is True
    assert analysis["llm_model"] == "test-model"
    assert result_store.get(response["analysis_id"])["analysis_result"]["llm_report"] == "LLM 리포트 본문"
