from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from src.app.core.config import PROJECT_ROOT
from src.app.schemas.analysis import VulnerabilityFinding
from src.app.services.analyzer_service import AnalyzerService

EXPECTED_TYPES = {
    "SQL_INJECTION",
    "XSS",
    "HARDCODED_SECRET",
    "PATH_TRAVERSAL",
    "COMMAND_INJECTION",
    "INSECURE_RANDOM",
    "WEAK_HASH",
}


def test_sample_analysis_detects_expected_java_findings() -> None:
    result = AnalyzerService(PROJECT_ROOT).analyze("src/analyzer/test_samples")
    analysis = result["analysis_result"]
    assert analysis["files_analyzed"] == 7
    assert analysis["summary"]["total_vulnerabilities"] == 21
    assert {finding["type"] for finding in analysis["vulnerabilities"]} == EXPECTED_TYPES
    for finding in analysis["vulnerabilities"]:
        assert finding["description"]
        assert finding["recommendation"]
        assert finding["cwe"]
        assert finding["guide_source"] == "행정안전부 「소프트웨어 보안약점 진단가이드(2019.6. 개정)」"
        assert finding["guide_category"]
        assert finding["guide_item"]
        assert finding["confidence"] in {"HIGH", "MEDIUM", "LOW"}


def test_vulnerability_schema_requires_enriched_fields() -> None:
    base = {
        "id": "VULN-001",
        "type": "SQL_INJECTION",
        "severity": "HIGH",
        "file": "UserDAO.java",
        "line": 10,
        "function": "findUser",
        "code_snippet": "stmt.executeQuery(sql)",
        "call_chain": [],
        "description": "사용자 입력이 SQL에 직접 결합됩니다.",
        "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
    }

    for required_field in (
        "cwe",
        "guide_source",
        "guide_category",
        "guide_item",
        "recommendation",
        "safe_example",
        "confidence",
    ):
        payload = {
            **base,
            "cwe": "CWE-89",
            "guide_source": "행정안전부 「소프트웨어 보안약점 진단가이드(2019.6. 개정)」",
            "guide_category": "입력데이터 검증 및 표현",
            "guide_item": "SQL 삽입",
            "recommendation": "PreparedStatement를 사용하세요.",
            "safe_example": "PreparedStatement ps = conn.prepareStatement(sql);",
            "confidence": "HIGH",
        }
        payload.pop(required_field)
        with pytest.raises(ValidationError):
            VulnerabilityFinding.model_validate(payload)


def test_xss_detector_tracks_sanitized_output_flow(tmp_path: Path) -> None:
    sample = tmp_path / "XssFlowController.java"
    sample.write_text(
        """
import javax.servlet.http.*;
import java.io.*;

public class XssFlowController {
    public void unsafe(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String keyword = req.getParameter("q");
        String decorated = keyword;
        resp.getWriter().println("<h2>" + decorated + "</h2>");
    }

    public void safeByApacheEscape(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String keyword = req.getParameter("q");
        String safeKeyword = StringEscapeUtils.escapeHtml4(keyword);
        resp.getWriter().println("<h2>" + safeKeyword + "</h2>");
    }

    public void safeByOwaspEncoder(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String keyword = req.getParameter("q");
        String safeKeyword = Encode.forHtml(keyword);
        resp.getWriter().println("<h2>" + safeKeyword + "</h2>");
    }

    public void safeBySpringHtmlUtils(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String keyword = req.getParameter("q");
        keyword = HtmlUtils.htmlEscape(keyword);
        resp.getWriter().println("<h2>" + keyword + "</h2>");
    }
}
""".strip(),
        encoding="utf-8",
    )

    result = AnalyzerService(tmp_path).analyze(str(sample))
    findings = result["analysis_result"]["vulnerabilities"]

    assert [finding["type"] for finding in findings] == ["XSS"]
    assert findings[0]["function"] == "unsafe"
    assert "decorated" in findings[0]["code_snippet"]


def test_hardcoded_secret_requires_sensitive_usage_flow(tmp_path: Path) -> None:
    sample = tmp_path / "SecretFlowController.java"
    sample.write_text(
        """
import java.sql.*;

public class SecretFlowController {
    private String unusedPassword = "not-used-1234";
    private String returnedToken = "return-only-token";
    private String copiedSecret = "copied-secret";
    private String dbPassword = "root1234!";

    public String returnToken() {
        return returnedToken;
    }

    public void copyOnly() {
        String localSecret = copiedSecret;
    }

    public Connection connect() throws Exception {
        return DriverManager.getConnection("jdbc:mysql://localhost/db", "root", dbPassword);
    }
}
""".strip(),
        encoding="utf-8",
    )

    result = AnalyzerService(tmp_path).analyze(str(sample))
    findings = [
        finding
        for finding in result["analysis_result"]["vulnerabilities"]
        if finding["type"] == "HARDCODED_SECRET"
    ]

    assert len(findings) == 1
    assert findings[0]["code_snippet"] == 'private String dbPassword = "root1234!";'
    assert findings[0]["call_chain"] == [
        "SecretFlowController.connect",
        "getConnection",
        "선언 line 7",
        "사용 line 17",
    ]


def test_sql_injection_requires_tainted_sql_execution_flow(tmp_path: Path) -> None:
    sample = tmp_path / "SqlFlowController.java"
    sample.write_text(
        """
import java.sql.*;
import javax.servlet.http.*;

public class SqlFlowController {
    public ResultSet unsafeConcat(String userId, Statement stmt) throws Exception {
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        return stmt.executeQuery(query);
    }

    public ResultSet unsafeFormat(String username, Statement stmt) throws Exception {
        String query = String.format("SELECT * FROM users WHERE username = '%s'", username);
        return stmt.executeQuery(query);
    }

    public ResultSet unsafeConcatMethod(HttpServletRequest req, Statement stmt) throws Exception {
        String userId = req.getParameter("id");
        String query = "SELECT * FROM users WHERE id = '".concat(userId).concat("'");
        return stmt.executeQuery(query);
    }

    public ResultSet safePrepared(String userId, Connection conn) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, userId);
        return ps.executeQuery();
    }

    public ResultSet safeConstantConcat(Statement stmt) throws Exception {
        String query = "SELECT * " + "FROM users";
        return stmt.executeQuery(query);
    }
}
""".strip(),
        encoding="utf-8",
    )

    result = AnalyzerService(tmp_path).analyze(str(sample))
    findings = [
        finding
        for finding in result["analysis_result"]["vulnerabilities"]
        if finding["type"] == "SQL_INJECTION"
    ]

    assert [finding["function"] for finding in findings] == [
        "unsafeConcat",
        "unsafeFormat",
        "unsafeConcatMethod",
    ]
    assert all("executeQuery" in finding["call_chain"][-1] for finding in findings)
