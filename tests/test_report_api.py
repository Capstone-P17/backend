from __future__ import annotations


def vulnerable_java_bytes() -> bytes:
    return (
        b"public class LoginService { "
        b"public void authenticate(String username) { "
        b"String query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"; "
        b"cursor.executeQuery(query); "
        b"} "
        b"}"
    )


def test_report_download_returns_pdf(client) -> None:
    analysis_response = client.post(
        "/analyze/file",
        files={"file": ("LoginService.java", vulnerable_java_bytes(), "text/plain")},
    )
    assert analysis_response.status_code == 200
    analysis_id = analysis_response.json()["analysis_id"]

    response = client.get(f"/report/{analysis_id}")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert "attachment;" in response.headers["content-disposition"]
    assert response.content.startswith(b"%PDF")


def test_report_download_exposes_content_disposition_for_cors(client) -> None:
    analysis_response = client.post(
        "/analyze/file",
        files={"file": ("LoginService.java", vulnerable_java_bytes(), "text/plain")},
    )
    assert analysis_response.status_code == 200
    analysis_id = analysis_response.json()["analysis_id"]

    response = client.get(
        f"/report/{analysis_id}",
        headers={"Origin": "http://localhost:3000"},
    )

    assert response.status_code == 200
    assert response.headers["access-control-expose-headers"] == "Content-Disposition"


def test_report_download_returns_404_for_missing_analysis(client) -> None:
    response = client.get("/report/not-a-real-id")
    assert response.status_code == 404
