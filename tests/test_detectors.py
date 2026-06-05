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
    assert analysis["summary"]["total_vulnerabilities"] == 26
    assert {finding["type"] for finding in analysis["vulnerabilities"]} == EXPECTED_TYPES
    for finding in analysis["vulnerabilities"]:
        assert finding["description"]
        assert finding["recommendation"]
        assert finding["guide_source"] == "행정안전부 「소프트웨어 보안약점 진단가이드(2019.6. 개정)」"
        assert finding["guide_category"]
        assert finding["guide_item"]
        assert finding["cwe"].startswith("CWE-")
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
        "file": "UserDAO.java",
        "line": 10,
        "function": "findUser",
        "code_snippet": "stmt.executeQuery(sql)",
        "call_chain": [],
        "evidence": "sql 값이 stmt.executeQuery로 실행됩니다.",
        "description": "사용자 입력이 SQL에 직접 결합됩니다.",
    }

    for required_field in (
        "guide_source",
        "guide_category",
        "guide_item",
        "recommendation",
        "safe_example",
        "confidence",
    ):
        payload = {
            **base,
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


def test_xss_detector_tracks_branch_assignment_until_output(tmp_path: Path) -> None:
    sample = tmp_path / "XssBranchController.java"
    sample.write_text(
        """
import javax.servlet.http.*;
import java.io.*;

public class XssBranchController {
    public void bad(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String data;
        if (System.currentTimeMillis() > 0) {
            data = request.getParameter("name");
        } else {
            data = null;
        }

        if (data != null) {
            response.getWriter().println("<br>bad() - <img src=\\"" + data + "\\">");
        }
    }

    public void good(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String data;
        if (System.currentTimeMillis() > 0) {
            data = "foo";
        } else {
            data = null;
        }

        if (data != null) {
            response.getWriter().println("<br>good() - <img src=\\"" + data + "\\">");
        }
    }
}
""".strip(),
        encoding="utf-8",
    )

    result = AnalyzerService(tmp_path).analyze(str(sample))
    findings = [
        finding
        for finding in result["analysis_result"]["vulnerabilities"]
        if finding["type"] == "XSS"
    ]

    assert [finding["function"] for finding in findings] == ["bad"]
    assert "data" in findings[0]["call_chain"][0]
    assert "HTML 이스케이프" in findings[0]["evidence"]


def test_xss_detector_tracks_header_enumeration_into_format_output(tmp_path: Path) -> None:
    sample = tmp_path / "XssFormatController.java"
    sample.write_text(
        """
import java.io.*;
import java.util.*;
import javax.servlet.http.*;

public class XssFormatController {
    public void unsafeFormat(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        String param = "";
        Enumeration<String> headers = request.getHeaders("Referer");
        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement();
        }
        param = java.net.URLDecoder.decode(param, "UTF-8");
        Object[] obj = {"a", "b"};
        response.getWriter().format(Locale.US, param, obj);
    }

    public void safePlainTextFormat(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("text/plain;charset=UTF-8");
        String param = request.getHeader("Referer");
        response.getWriter().format(Locale.US, param);
    }
}
""".strip(),
        encoding="utf-8",
    )

    result = AnalyzerService(tmp_path).analyze(str(sample))
    findings = [
        finding
        for finding in result["analysis_result"]["vulnerabilities"]
        if finding["type"] == "XSS"
    ]

    assert [finding["function"] for finding in findings] == ["unsafeFormat"]
    assert "format" in findings[0]["code_snippet"]
    assert "getHeaders" in findings[0]["call_chain"][0]
    assert "HTML 응답" in findings[0]["evidence"]


def test_file_upload_detector_requires_allowlist_before_storage(tmp_path: Path) -> None:
    sample = tmp_path / "UploadController.java"
    sample.write_text(
        """
import java.io.*;
import javax.imageio.ImageIO;
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

    public void unsafeContentTypeOnly(MultipartFile file) throws IOException {
        Set<String> allowedContentTypes = Set.of("image/png", "image/jpeg");
        String contentType = file.getContentType();
        if (!allowedContentTypes.contains(contentType)) {
            throw new SecurityException("Unsupported upload type");
        }
        file.transferTo(Paths.get("uploads", "content-type-only.tmp"));
    }

    public void partialExtensionOnly(MultipartFile file) throws IOException {
        Set<String> allowedExtensions = Set.of("png", "jpg");
        String originalName = file.getOriginalFilename();
        String ext = originalName.substring(originalName.lastIndexOf(".") + 1);
        if (!allowedExtensions.contains(ext)) {
            throw new SecurityException("Unsupported upload type");
        }
        file.transferTo(Paths.get("uploads", "safe." + ext));
    }

    public void safeUpload(MultipartFile file) throws IOException {
        long maxUploadBytes = 1024 * 1024;
        if (file.getSize() > maxUploadBytes) {
            throw new SecurityException("Upload too large");
        }
        Set<String> allowedExtensions = Set.of("png", "jpg");
        String originalName = file.getOriginalFilename();
        String ext = originalName.substring(originalName.lastIndexOf(".") + 1).toLowerCase(Locale.ROOT);
        if (!allowedExtensions.contains(ext)) {
            throw new SecurityException("Unsupported upload type");
        }
        if (ImageIO.read(file.getInputStream()) == null) {
            throw new SecurityException("Invalid file signature");
        }
        String savedName = UUID.randomUUID().toString() + "." + ext;
        file.transferTo(Paths.get("/var/app/private-files", savedName));
        Paths.get("/var/app/private-files", savedName).toFile().setExecutable(false, false);
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

    assert [finding["function"] for finding in findings] == [
        "unsafeTransfer",
        "unsafeCopy",
        "unsafeContentTypeOnly",
        "partialExtensionOnly",
    ]
    assert all(finding["guide_item"] == "위험한 형식 파일 업로드" for finding in findings)
    assert all("파일 시그니쳐/Magic byte 검증" in finding["evidence"] for finding in findings)
    assert all("파일 크기 제한" in finding["evidence"] for finding in findings)
    assert all("파일 개수 제한" in finding["evidence"] for finding in findings)
    assert all("파일명 재생성" in finding["evidence"] for finding in findings)
    assert all("실행권한 제거" in finding["evidence"] for finding in findings)
    assert all("다운로드 검증" in finding["evidence"] for finding in findings)

    content_type_only = next(finding for finding in findings if finding["function"] == "unsafeContentTypeOnly")
    assert "Content-Type 검증: 확인됨" in content_type_only["evidence"]
    assert "단독 방어로는 부족" in content_type_only["evidence"]

    extension_only = next(finding for finding in findings if finding["function"] == "partialExtensionOnly")
    assert "확장자 검증: 허용목록 기반 검증이 확인되었습니다." in extension_only["evidence"]
    assert "파일 시그니쳐/Magic byte 검증: 미확인" in extension_only["evidence"]
    assert "실행권한 제거: 미확인" in extension_only["evidence"]


def test_hardcoded_secret_detects_declaration_even_without_sensitive_usage(tmp_path: Path) -> None:
    sample = tmp_path / "SecretFlowController.java"
    sample.write_text(
        """
import java.sql.*;

public class SecretFlowController {
    private String unusedPassword = "not-used-1234";
    private String returnedToken = "return-only-token";
    private String copiedSecret = "copied-secret";
    private String dbPassword = "root1234!";
    private String injectedPassword = "${DB_PASSWORD}";

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

    expected_declarations = [
        'private String unusedPassword = "not-used-1234";',
        'private String returnedToken = "return-only-token";',
        'private String copiedSecret = "copied-secret";',
        'private String dbPassword = "root1234!";',
    ]
    assert len(findings) == len(expected_declarations)
    for finding, declaration in zip(findings, expected_declarations, strict=True):
        assert declaration in finding["code_snippet"]
        assert "|" in finding["code_snippet"]

    db_password = findings[-1]
    assert db_password["call_chain"] == [
        "SecretFlowController.connect",
        "getConnection",
        "선언 line 7",
        "사용 line 19",
    ]
    assert db_password["confidence"] == "HIGH"
    assert "`dbPassword`" in db_password["evidence"]
    assert "getConnection" in db_password["evidence"]

    declarations_without_usage = findings[:3]
    assert all("사용처 확인 안 됨" in finding["call_chain"] for finding in declarations_without_usage)
    assert all("사용 여부와 무관하게" in finding["evidence"] or "현재 분석 범위에서 민감 호출 사용처는 확인되지 않았습니다" in finding["evidence"] for finding in declarations_without_usage)
    assert not any("injectedPassword" in finding["code_snippet"] for finding in findings)


def test_hardcoded_secret_tracks_generic_assignment_into_sensitive_usage(tmp_path: Path) -> None:
    sample = tmp_path / "SecretAssignmentController.java"
    sample.write_text(
        """
import java.io.*;
import java.sql.*;

public class SecretAssignmentController {
    public void bad() throws Exception {
        String data;
        data = "7e5tc4s3";
        DriverManager.getConnection("jdbc:h2:mem:test", "root", data);
    }

    public void safeConsole() throws Exception {
        String data;
        data = "";
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        data = reader.readLine();
        DriverManager.getConnection("jdbc:h2:mem:test", "root", data);
    }

    public void safeShortPlaceholder() throws Exception {
        String data;
        data = "foo";
        DriverManager.getConnection("jdbc:h2:mem:test", "root", data);
    }

    public void safeOverwrittenBeforeUse() throws Exception {
        String data;
        data = "temporary123";
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        data = reader.readLine();
        DriverManager.getConnection("jdbc:h2:mem:test", "root", data);
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

    assert [finding["function"] for finding in findings] == ["bad"]
    finding = findings[0]
    assert 'data = "7e5tc4s3"' in finding["code_snippet"]
    assert finding["call_chain"] == [
        "SecretAssignmentController.bad",
        "getConnection",
        "할당 line 7",
        "사용 line 8",
    ]
    assert "할당되었습니다" in finding["evidence"]
    assert "getConnection" in finding["evidence"]
    assert finding["confidence"] == "HIGH"


def test_weak_hash_detects_unsalted_password_hash_but_ignores_checksum(tmp_path: Path) -> None:
    sample = tmp_path / "CryptoPolicyService.java"
    sample.write_text(
        """
import java.security.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class CryptoPolicyService {
    public byte[] unsafeWeakAlgorithm(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return digest.digest(input.getBytes());
    }

    public byte[] unsafePasswordHash(String password) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(password.getBytes());
    }

    public byte[] safeChecksum(byte[] fileBytes) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(fileBytes);
    }

    public byte[] safePasswordHash(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 120000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }
}
""".strip(),
        encoding="utf-8",
    )

    result = AnalyzerService(tmp_path).analyze(str(sample))
    findings = [
        finding
        for finding in result["analysis_result"]["vulnerabilities"]
        if finding["type"] == "WEAK_HASH"
    ]

    assert [finding["function"] for finding in findings] == [
        "unsafeWeakAlgorithm",
        "unsafePasswordHash",
    ]
    weak_algorithm, password_hash = findings
    assert "MD5" in weak_algorithm["evidence"]
    assert weak_algorithm["confidence"] == "HIGH"
    assert "salt/KDF 없는 비밀번호 해시" in password_hash["call_chain"]
    assert "PBKDF2" in password_hash["recommendation"]
    assert password_hash["confidence"] == "MEDIUM"
    assert not any(finding["function"] == "safeChecksum" for finding in findings)
    assert not any(finding["function"] == "safePasswordHash" for finding in findings)


def test_path_traversal_tracks_cookie_value_through_intermediate_filename(tmp_path: Path) -> None:
    sample = tmp_path / "PathFlowController.java"
    sample.write_text(
        """
import java.io.*;
import javax.servlet.http.*;

public class PathFlowController {
    public void unsafeCookieFile(HttpServletRequest request) throws Exception {
        Cookie[] theCookies = request.getCookies();
        String param = "noCookieValueSupplied";
        if (theCookies != null) {
            for (Cookie theCookie : theCookies) {
                if (theCookie.getName().equals("target")) {
                    param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
                    break;
                }
            }
        }
        String fileName = "/var/app/files/" + param;
        FileInputStream fis = new FileInputStream(new File(fileName));
    }

    public void safeConstantFile() throws Exception {
        String fileName = "/var/app/files/help.txt";
        FileInputStream fis = new FileInputStream(new File(fileName));
    }
}
""".strip(),
        encoding="utf-8",
    )

    result = AnalyzerService(tmp_path).analyze(str(sample))
    findings = [
        finding
        for finding in result["analysis_result"]["vulnerabilities"]
        if finding["type"] == "PATH_TRAVERSAL"
    ]

    assert [finding["function"] for finding in findings] == ["unsafeCookieFile"]
    finding = findings[0]
    assert "param" in finding["call_chain"][-1]
    assert "fileName" in finding["call_chain"][-1]
    assert "FileInputStream" in finding["call_chain"][-1]
    assert "경로 변수" in finding["evidence"]
    assert "FileInputStream" in finding["confidence_reason"]
    assert not any(finding["function"] == "safeConstantFile" for finding in findings)


def test_command_injection_tracks_tainted_list_into_process_builder_command(tmp_path: Path) -> None:
    sample = tmp_path / "CommandListController.java"
    sample.write_text(
        """
import java.io.*;
import java.util.*;
import javax.servlet.http.*;

public class CommandListController {
    public void unsafeListCommand(HttpServletRequest request) throws IOException {
        String param = "";
        if (request.getHeader("cmd") != null) {
            param = request.getHeader("cmd");
        }
        param = java.net.URLDecoder.decode(param, "UTF-8");
        List<String> argList = new ArrayList<>();
        argList.add("sh");
        argList.add("-c");
        argList.add("echo " + param);
        ProcessBuilder pb = new ProcessBuilder();
        pb.command(argList);
        pb.start();
    }

    public void safeConstantList() throws IOException {
        List<String> argList = new ArrayList<>();
        argList.add("sh");
        argList.add("-c");
        argList.add("echo safe");
        ProcessBuilder pb = new ProcessBuilder();
        pb.command(argList);
        pb.start();
    }
}
""".strip(),
        encoding="utf-8",
    )

    result = AnalyzerService(tmp_path).analyze(str(sample))
    findings = [
        finding
        for finding in result["analysis_result"]["vulnerabilities"]
        if finding["type"] == "COMMAND_INJECTION"
    ]

    assert [finding["function"] for finding in findings] == ["unsafeListCommand"]
    finding = findings[0]
    assert "param" in finding["call_chain"][-1]
    assert "argList" in finding["call_chain"][-1]
    assert "ProcessBuilder.command" in finding["call_chain"][-1]
    assert "명령 인자 컬렉션" in finding["evidence"]
    assert "ProcessBuilder.command" in finding["confidence_reason"]
    assert not any(finding["function"] == "safeConstantList" for finding in findings)


def test_insecure_random_requires_security_context(tmp_path: Path) -> None:
    sample = tmp_path / "RandomPolicyService.java"
    sample.write_text(
        """
import java.util.Random;
import java.security.SecureRandom;

public class RandomPolicyService {
    public String generateToken() {
        Random random = new Random();
        return String.valueOf(random.nextLong());
    }

    public String createSession() {
        Random sessionRandom = new Random();
        return "S-" + sessionRandom.nextInt();
    }

    public int rollDice() {
        Random random = new Random();
        return random.nextInt(6) + 1;
    }

    public int randomPage() {
        Random pager = new Random();
        return pager.nextInt(100);
    }

    public String secureToken() {
        SecureRandom secureRandom = new SecureRandom();
        return String.valueOf(secureRandom.nextLong());
    }
}
""".strip(),
        encoding="utf-8",
    )

    result = AnalyzerService(tmp_path).analyze(str(sample))
    findings = [
        finding
        for finding in result["analysis_result"]["vulnerabilities"]
        if finding["type"] == "INSECURE_RANDOM"
    ]

    assert [finding["function"] for finding in findings] == ["generateToken", "createSession"]
    assert "메서드명 `generateToken`의 보안값 생성 문맥" in findings[0]["evidence"]
    assert "변수명 `sessionRandom`의 보안값 생성 문맥" in findings[1]["evidence"]
    assert all("new Random()" in finding["confidence_reason"] for finding in findings)


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

    public int unsafeUpdate(String username, Statement stmt) throws Exception {
        String query = "UPDATE users SET name = '" + username + "'";
        return stmt.executeUpdate(query);
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

    public ResultSet safeSelectedWord(String userId, Statement stmt) throws Exception {
        String query = "User selected " + userId;
        return stmt.executeQuery(query);
    }

    public ResultSet safeSqlKeywordInComment(String userId, Statement stmt) throws Exception {
        // SELECT * FROM users WHERE id = user input
        String query = "not a query " + userId;
        return stmt.executeQuery(query);
    }

    public ResultSet safeLogMessage(String userId, Statement stmt) throws Exception {
        String message = "SELECT request for " + userId;
        System.out.println(message);
        return stmt.executeQuery("SELECT * FROM audit_log");
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
        "unsafeUpdate",
    ]
    assert all(
        any(method in finding["call_chain"][-1] for method in ("executeQuery", "executeUpdate"))
        for finding in findings
    )
    assert all(finding["call_chain_details"] for finding in findings)
    assert findings[0]["call_chain_details"][0]["kind"] == "function"
    assert findings[0]["call_chain_details"][0]["file"] == "SqlFlowController.java"
    assert findings[0]["call_chain_details"][0]["function"] == "unsafeConcat"
    assert findings[0]["call_chain_details"][-1]["kind"] == "sink"
    assert findings[0]["call_chain_details"][-1]["line"] > findings[0]["line"]
    assert "executeQuery" in findings[0]["call_chain_details"][-1]["label"]
    assert all(any(method in finding["evidence"] for method in ("executeQuery", "executeUpdate")) for finding in findings)
    assert any("String.format" in finding["code_snippet"] for finding in findings)
    assert all("|" in finding["code_snippet"] for finding in findings)
    unsafe_concat = findings[0]["code_snippet"]
    assert "String query" in unsafe_concat
    assert ">" in unsafe_concat and "executeQuery" in unsafe_concat


def test_sql_injection_tracks_taint_across_same_file_method_call(tmp_path: Path) -> None:
    sample = tmp_path / "SqlInterproceduralController.java"
    sample.write_text(
        """
import java.sql.*;
import javax.servlet.http.*;

public class SqlInterproceduralController {
    public ResultSet route(HttpServletRequest req, Statement stmt) throws Exception {
        String userId = req.getParameter("id");
        return findById(userId, stmt);
    }

    private ResultSet findById(String id, Statement stmt) throws Exception {
        String query = "SELECT * FROM users WHERE id = '" + id + "'";
        return stmt.executeQuery(query);
    }

    public ResultSet safeRoute(HttpServletRequest req, Statement stmt) throws Exception {
        return findStatic(stmt);
    }

    private ResultSet findStatic(Statement stmt) throws Exception {
        String query = "SELECT * FROM users";
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

    interprocedural = [
        finding
        for finding in findings
        if finding["function"] == "route" and "inter-procedural" in finding["confidence_reason"]
    ]

    assert [finding["function"] for finding in findings] == ["findById", "route"]
    assert interprocedural
    assert "findById(...)" in interprocedural[0]["evidence"]
    assert "userId` → `id" in interprocedural[0]["evidence"]
    assert "SqlInterproceduralController.findById" in interprocedural[0]["call_chain"]
    assert not any(finding["function"] == "safeRoute" for finding in findings)


def test_sql_injection_tracks_taint_across_controller_service_dao_files(tmp_path: Path) -> None:
    (tmp_path / "UserController.java").write_text(
        """
import java.sql.*;
import javax.servlet.http.*;

public class UserController {
    private UserService userService;

    public ResultSet search(HttpServletRequest req, Statement stmt) throws Exception {
        String id = req.getParameter("id");
        return userService.findUser(id, stmt);
    }

    public ResultSet safeSearch(HttpServletRequest req, Connection conn) throws Exception {
        String id = req.getParameter("id");
        return userService.findUserSafely(id, conn);
    }

    public ResultSet overloadedSafeSearch(HttpServletRequest req, Connection conn) throws Exception {
        String id = req.getParameter("id");
        return userService.findUser(id);
    }
}
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "UserService.java").write_text(
        """
import java.sql.*;

public class UserService {
    private UserDao dao;

    public ResultSet findUser(String id, Statement stmt) throws Exception {
        return dao.findById(id, stmt);
    }

    public ResultSet findUser(String id) throws Exception {
        return dao.findStatic();
    }

    public ResultSet findUserSafely(String id, Connection conn) throws Exception {
        return dao.findByIdSafely(id, conn);
    }
}
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "UserDao.java").write_text(
        """
import java.sql.*;

public class UserDao {
    public ResultSet findById(String id, Statement stmt) throws Exception {
        String query = "SELECT * FROM users WHERE id = '" + id + "'";
        return stmt.executeQuery(query);
    }

    public ResultSet findByIdSafely(String id, Connection conn) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);
        return ps.executeQuery();
    }

    public ResultSet findStatic() throws Exception {
        Statement stmt = null;
        String query = "SELECT * FROM users";
        return stmt.executeQuery(query);
    }
}
""".strip(),
        encoding="utf-8",
    )

    result = AnalyzerService(tmp_path).analyze(str(tmp_path))
    findings = [
        finding
        for finding in result["analysis_result"]["vulnerabilities"]
        if finding["type"] == "SQL_INJECTION"
    ]

    controller_findings = [
        finding
        for finding in findings
        if finding["function"] == "search" and "클래스/파일 경계를 넘는" in finding["confidence_reason"]
    ]

    assert controller_findings
    assert "UserController.search" in controller_findings[0]["call_chain"]
    assert "UserService.findUser" in controller_findings[0]["call_chain"]
    assert "UserDao.findById" in controller_findings[0]["call_chain"]
    assert "stmt.executeQuery" in controller_findings[0]["call_chain"][-1]
    assert "findUser(...)" in controller_findings[0]["evidence"]
    assert not any(finding["function"] == "safeSearch" for finding in findings)
    assert not any(finding["function"] == "overloadedSafeSearch" for finding in findings)
