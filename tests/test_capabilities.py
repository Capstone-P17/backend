from __future__ import annotations


def test_capabilities_is_public_and_java_rule_based(unauthenticated_client) -> None:
    response = unauthenticated_client.get("/capabilities")
    assert response.status_code == 200
    payload = response.json()
    assert payload["service"] == "java-security-static-analysis"
    assert payload["supported_languages"] == ["java"]
    assert payload["supported_file_extensions"] == [".java"]
    assert payload["analysis_mode"] == "rule_based_static_analysis"
    assert payload["llm_detection_enabled"] is False
    assert payload["llm_used_for_detection"] is False
    assert payload["llm_provider"] == "openai"
    assert payload["static_analysis_available"] is True
    assert payload["llm_report_available"] is False
    assert {detector["type"] for detector in payload["detectors"]} == {
        "SQL_INJECTION",
        "XSS",
        "HARDCODED_SECRET",
        "PATH_TRAVERSAL",
        "COMMAND_INJECTION",
        "INSECURE_RANDOM",
        "WEAK_HASH",
        "DANGEROUS_FILE_UPLOAD",
    }
