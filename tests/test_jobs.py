from __future__ import annotations


def fake_analysis_response() -> dict:
    return {
        "analysis_id": "analysis-123",
        "analysis_result": {
            "repository": "repo",
            "target_path": None,
            "analyzed_at": "2026-01-01T00:00:00",
            "language": "java",
            "files_analyzed": 1,
            "vulnerabilities": [],
            "call_graph": {},
            "summary": {
                "total_vulnerabilities": 0,
                "by_type": {},
                "score": {"overall": 100, "by_file": {}},
            },
        },
    }


def test_repository_job_success_path(client, analysis_service) -> None:
    def analyze(url: str, user_id: int, progress_callback=None) -> dict:  # noqa: ANN001
        if progress_callback:
            progress_callback(
                {
                    "phase": "report_generation",
                    "message": "finding별 상세 리포트를 생성하고 있습니다. (1/2)",
                    "progress": {
                        "percent": 82,
                        "findings_total": 2,
                        "finding_reports_completed": 1,
                        "finding_reports_total": 2,
                    },
                }
            )
        return fake_analysis_response()

    analysis_service.analyze_github_repository = analyze  # type: ignore[method-assign]
    response = client.post("/analyze/repository/jobs", json={"url": "https://github.com/acme/repo"})
    assert response.status_code == 202
    payload = response.json()
    assert payload["status"] == "queued"

    status_response = client.get(f"/analyze/jobs/{payload['job_id']}")
    assert status_response.status_code == 200
    status_payload = status_response.json()
    assert status_payload["status"] == "succeeded"
    assert status_payload["phase"] == "succeeded"
    assert status_payload["message"] == "분석과 finding별 리포트 생성이 완료되었습니다."
    assert status_payload["progress"]["percent"] == 100
    assert status_payload["progress"]["finding_reports_total"] == 2
    assert status_payload["analysis_id"] == "analysis-123"


def test_repository_job_failure_path(client, analysis_service) -> None:
    def fail(url: str, user_id: int, progress_callback=None) -> dict:  # noqa: ANN001
        raise RuntimeError("boom")

    analysis_service.analyze_github_repository = fail  # type: ignore[method-assign]
    response = client.post("/analyze/repository/jobs", json={"url": "https://github.com/acme/repo"})
    assert response.status_code == 202
    job_id = response.json()["job_id"]

    status_response = client.get(f"/analyze/jobs/{job_id}")
    assert status_response.status_code == 200
    assert status_response.json()["status"] == "failed"
    assert status_response.json()["phase"] == "failed"
    assert status_response.json()["message"] == "분석 작업이 실패했습니다."
    assert status_response.json()["error"] == "boom"


def test_unknown_job_returns_404(client) -> None:
    assert client.get("/analyze/jobs/missing").status_code == 404
