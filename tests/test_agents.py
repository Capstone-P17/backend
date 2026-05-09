from __future__ import annotations


def test_agent_profile_exposes_llm_availability(client) -> None:
    response = client.get("/agents/profile")
    assert response.status_code == 200
    payload = response.json()
    assert payload["openai_configured"] is False
    assert payload["llm_report_available"] is False


def test_agent_run_without_openai_key_returns_clear_503(client) -> None:
    response = client.post("/agents/runs", json={"target_path": "src/analyzer/test_samples"})
    assert response.status_code == 503
    assert response.json()["detail"] == "LLM 리포트 생성을 위한 OPENAI_API_KEY가 설정되어 있지 않습니다."
