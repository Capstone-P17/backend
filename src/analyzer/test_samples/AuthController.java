import java.sql.*;
import javax.servlet.http.*;
import java.io.*;

public class AuthController {

    // 탐지 대상: 하드코딩 비밀번호
    private String secretKey = "my-secret-key-12345";
    private String dbPassword = "root1234!";

    // 탐지 제외: 비밀번호가 아닌 일반 설정값
    private String appName = "VulnScanner";
    private int maxRetry = 3;

    // 탐지 대상: SQL Injection (String.format)
    public User login(String username, String password) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", dbPassword);
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        ResultSet rs = stmt.executeQuery(query);
        return mapUser(rs);
    }

    // 탐지 대상: SQL Injection (DELETE)
    public void deleteUser(String userId) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", dbPassword);
        Statement stmt = conn.createStatement();
        String query = "DELETE FROM users WHERE id = '" + userId + "'";
        stmt.executeUpdate(query);
    }

    // 탐지 제외: PreparedStatement 사용 (안전)
    public User safeLogin(String username, String password) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", dbPassword);
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE username = ? AND password = ?");
        pstmt.setString(1, username);
        pstmt.setString(2, password);
        return mapUser(pstmt.executeQuery());
    }

    // 탐지 대상: XSS (에러 메시지에 사용자 입력 포함)
    public void showError(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String errorMsg = req.getParameter("error");
        resp.getWriter().println("<div class='error'>" + errorMsg + "</div>");
    }

    // 탐지 대상: XSS (검색어 반영)
    public void searchResult(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String keyword = req.getParameter("q");
        resp.getWriter().println("<h2>검색 결과: " + keyword + "</h2>");
    }

    // 탐지 제외: 안전한 입력 처리
    public void safeInput(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        resp.getWriter().println("Hello, user");
    }

    // 탐지 제외: 안전한 출력 (사용자 입력 미포함)
    public void safeOutput(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.getWriter().println("<h1>Welcome to our site</h1>");
    }

    private User mapUser(ResultSet rs) { return new User(); }
}
