import java.sql.*;
import javax.servlet.http.*;
import java.io.*;

public class OrderService {

    // 하드코딩 비밀번호
    private String apiToken = "Bearer sk-live-abc123xyz";

    // SQL Injection - String.format 패턴
    public Order getOrder(String orderId) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", "pass");
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM orders WHERE order_id = " + orderId;
        ResultSet rs = stmt.executeQuery(sql);
        return mapOrder(rs);
    }

    // XSS - getHeader 패턴
    public void showUserAgent(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String ua = req.getHeader("User-Agent");
        resp.getWriter().println("<div>Your browser: " + ua + "</div>");
    }

    // 안전한 코드
    public Order getSafeOrder(String orderId) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", "pass");
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM orders WHERE order_id = ?");
        pstmt.setString(1, orderId);
        return mapOrder(pstmt.executeQuery());
    }

    private Order mapOrder(ResultSet rs) {
        return new Order();
    }
}
