from __future__ import annotations


def java_bytes() -> bytes:
    return b"public class SafeApi { public void ok() { System.out.println(\"ok\"); } }"


def vulnerable_java_bytes() -> bytes:
    return (
        b"public class LoginService { "
        b"public void authenticate(String username) { "
        b"String query = \"SELECT * FROM users WHERE username = '\" + username + \"'\"; "
        b"cursor.executeQuery(query); "
        b"} "
        b"}"
    )


def test_analyze_file_response_and_result_endpoints(client) -> None:
    response = client.post(
        "/analyze/file",
        files={"file": ("SafeApi.java", java_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    payload = response.json()
    analysis_id = payload["analysis_id"]
    assert payload["analysis_result"]["files_analyzed"] == 1

    latest = client.get("/result")
    assert latest.status_code == 200
    assert latest.json()["analysis_id"] == analysis_id

    by_id = client.get(f"/result/{analysis_id}")
    assert by_id.status_code == 200
    assert by_id.json()["analysis_result"]["language"] == "java"

    missing = client.get("/result/not-a-real-id")
    assert missing.status_code == 404

    listing = client.get("/results")
    assert listing.status_code == 200
    assert listing.json()["results"][0]["analysis_id"] == analysis_id


def test_file_detail_endpoint_returns_single_file_findings(client) -> None:
    response = client.post(
        "/analyze/file",
        files={"file": ("LoginService.java", vulnerable_java_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    analysis_id = response.json()["analysis_id"]

    detail = client.get(f"/result/{analysis_id}/files/LoginService.java")
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["analysis_id"] == analysis_id
    assert payload["file_id"] == "LoginService.java"
    assert payload["file_path"] == "LoginService.java"
    assert payload["summary"]["total_vulnerabilities"] >= 1
    assert payload["findings"]
    assert all(finding["file"] == "LoginService.java" for finding in payload["findings"])


def test_file_detail_endpoint_returns_404_for_missing_file(client) -> None:
    response = client.post(
        "/analyze/file",
        files={"file": ("LoginService.java", vulnerable_java_bytes(), "text/plain")},
    )
    assert response.status_code == 200
    analysis_id = response.json()["analysis_id"]

    missing = client.get(f"/result/{analysis_id}/files/Unknown.java")
    assert missing.status_code == 404


def test_existing_protected_routes_still_require_auth(unauthenticated_client) -> None:
    assert unauthenticated_client.get("/result").status_code == 401
    assert unauthenticated_client.get("/results").status_code == 401
    assert unauthenticated_client.get("/report/some-id").status_code == 401
    assert unauthenticated_client.get("/result/some-id/files/SafeApi.java").status_code == 401
    assert unauthenticated_client.post("/analyze/repository", json={"url": "https://github.com/acme/repo"}).status_code == 401
    assert unauthenticated_client.get("/agents/profile").status_code == 401
