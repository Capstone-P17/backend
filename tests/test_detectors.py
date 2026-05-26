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
    "DANGEROUS_FILE_UPLOAD",
}


def test_sample_analysis_detects_expected_java_findings() -> None:
    result = AnalyzerService(PROJECT_ROOT).analyze("src/analyzer/test_samples")
    analysis = result["analysis_result"]
    assert analysis["files_analyzed"] == 8
    assert analysis["summary"]["total_vulnerabilities"] == 23
    assert {finding["type"] for finding in analysis["vulnerabilities"]} == EXPECTED_TYPES
    for finding in analysis["vulnerabilities"]:
        assert finding["description"]
        assert finding["recommendation"]
        assert finding["cwe"]
        assert finding["guide_source"] == "행정안전부 「소프트웨어 보안약점 진단가이드(2019.6. 개정)」"
        assert finding["guide_category"]
        assert finding["guide_item"]
        assert finding["confidence"] in {"HIGH", "MEDIUM", "LOW"}
        assert finding["confidence_reason"]
        assert finding["evidence"]

    evidence_by_type = {
        finding["type"]: finding["evidence"]
        for finding in analysis["vulnerabilities"]
        if finding["type"] not in {"SQL_INJECTION", "XSS", "HARDCODED_SECRET", "DANGEROUS_FILE_UPLOAD"}
    }
    assert "정규화(normalize)" in evidence_by_type["PATH_TRAVERSAL"]
    assert "운영체제 명령 실행" in evidence_by_type["COMMAND_INJECTION"]
    assert "new Random()" in evidence_by_type["INSECURE_RANDOM"]
    assert "MessageDigest.getInstance" in evidence_by_type["WEAK_HASH"]


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
        "evidence": "sql 값이 stmt.executeQuery로 실행됩니다.",
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
            "confidence_reason": "외부 입력이 SQL 실행 API까지 도달합니다.",
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
    assert "decorated" in findings[0]["evidence"]
    assert "HTML 이스케이프" in findings[0]["evidence"]


def test_file_upload_detector_requires_allowlist_before_storage(tmp_path: Path) -> None:
    sample = tmp_path / "UploadController.java"
    sample.write_text(
        """
import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.springframework.web.multipart.MultipartFile;

public class UploadController {
    public void unsafeTransfer(MultipartFile file) throws IOException {
        Path target = Paths.get("uploads", "profile.tmp");
        file.transferTo(target);
    }

    public void unsafeCopy(MultipartFile file) throws IOException {
        Files.copy(file.getInputStream(), Paths.get("uploads", "document.tmp"));
    }

    public void safeUpload(MultipartFile file) throws IOException {
        Set<String> allowedExtensions = Set.of("png", "jpg");
        String originalName = file.getOriginalFilename();
        String ext = originalName.substring(originalName.lastIndexOf(".") + 1);
        if (!allowedExtensions.contains(ext)) {
            throw new SecurityException("Unsupported upload type");
        }
        file.transferTo(Paths.get("uploads", "safe." + ext));
    }
}
""".strip(),
        encoding="utf-8",
    )

    result = AnalyzerService(tmp_path).analyze(str(sample))
    findings = [
        finding
        for finding in result["analysis_result"]["vulnerabilities"]
        if finding["type"] == "DANGEROUS_FILE_UPLOAD"
    ]

    assert [finding["function"] for finding in findings] == ["unsafeTransfer", "unsafeCopy"]
    assert all(finding["guide_item"] == "위험한 형식 파일 업로드" for finding in findings)
    assert all("허용목록 검증" in finding["evidence"] for finding in findings)


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
        "사용 line 18",
    ]
    assert "`dbPassword`" in findings[0]["evidence"]
    assert "getConnection" in findings[0]["evidence"]


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
    assert all("executeQuery" in finding["evidence"] for finding in findings)
    assert any("String.format" in finding["code_snippet"] for finding in findings)
