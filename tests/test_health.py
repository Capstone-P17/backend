from __future__ import annotations


def test_health(unauthenticated_client) -> None:
    response = unauthenticated_client.get("/health", headers={"x-request-id": "test-request-id"})
    assert response.status_code == 200
    assert response.headers["x-request-id"] == "test-request-id"
    assert response.json()["status"] == "ok"
