from __future__ import annotations

from io import BytesIO
from zipfile import ZipFile

from src.app.services.analysis_service import AnalysisService


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


def test_uploaded_file_returns_analysis_id_envelope(analysis_service: AnalysisService) -> None:
    assert_analysis_response(analysis_service.analyze_uploaded_file("Safe.java", java_bytes()))


def test_uploaded_repository_returns_analysis_id_envelope(analysis_service: AnalysisService) -> None:
    assert_analysis_response(analysis_service.analyze_uploaded_repository("repo.zip", zip_bytes()))


def test_github_repository_returns_analysis_id_envelope_without_network(monkeypatch, analysis_service: AnalysisService) -> None:
    monkeypatch.setattr(analysis_service, "_download_github_archive", lambda owner, repo: (zip_bytes(), "main"))
    assert_analysis_response(analysis_service.analyze_github_repository("https://github.com/acme/repo"))
