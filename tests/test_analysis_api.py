from __future__ import annotations


def java_bytes() -> bytes:
    return b"public class SafeApi { public void ok() { System.out.println(\"ok\"); } }"


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


def test_existing_protected_routes_still_require_auth(unauthenticated_client) -> None:
    assert unauthenticated_client.get("/result").status_code == 401
    assert unauthenticated_client.get("/results").status_code == 401
    assert unauthenticated_client.post("/analyze/repository", json={"url": "https://github.com/acme/repo"}).status_code == 401
    assert unauthenticated_client.get("/agents/profile").status_code == 401
