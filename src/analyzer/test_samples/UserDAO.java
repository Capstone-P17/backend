import java.sql.*;
import javax.servlet.http.*;
import java.io.*;

public class UserDAO {

    // 취약점 1: Hard-coded Password
    private String dbPassword = "admin1234";

    // 취약점 2: SQL Injection
    public User getUser(String userId) throws Exception {
        Connection conn = DriverManager.getConnection(
            "jdbc:mysql://localhost/db", "root", dbPassword
        );
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        ResultSet rs = stmt.executeQuery(query);
        return mapUser(rs);
    }

    // 취약점 3: XSS
    public void renderProfile(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String username = req.getParameter("name");
        resp.getWriter().println("<h1>" + username + "</h1>");
    }

    // 안전한 함수 (탐지되면 안 됨)
    public User getSafeUser(String userId) throws Exception {
        PreparedStatement pstmt = conn.prepareStatement(
            "SELECT * FROM users WHERE id = ?"
        );
        pstmt.setString(1, userId);
        return mapUser(pstmt.executeQuery());
    }

    private User mapUser(ResultSet rs) {
        return new User();
    }
}
