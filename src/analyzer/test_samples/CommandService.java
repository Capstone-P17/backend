import java.io.*;
import javax.servlet.http.*;

public class CommandService {

    // 탐지 대상: Runtime.exec(userInput) - 외부 명령 직접 실행
    public String runCommand(HttpServletRequest req) throws IOException {
        String cmd = req.getParameter("cmd");
        Process proc = Runtime.getRuntime().exec(cmd);
        return new String(proc.getInputStream().readAllBytes());
    }

    // 탐지 대상: new ProcessBuilder(userInput) - 프로세스 빌더에 외부 입력
    public void pingHost(HttpServletRequest req) throws IOException {
        String host = req.getParameter("host");
        Process proc = new ProcessBuilder(host).start();
        proc.waitFor();
    }

    // 탐지 제외: 하드코딩된 명령어 (안전)
    public String listFiles() throws IOException {
        Process proc = Runtime.getRuntime().exec("ls -la /tmp");
        return new String(proc.getInputStream().readAllBytes());
    }

    // 탐지 제외: ProcessBuilder에 상수 인자 (안전)
    public void checkDisk() throws IOException {
        Process proc = new ProcessBuilder("df", "-h").start();
        proc.waitFor();
    }

    // 탐지 제외: 사용자 입력을 명령 실행 없이 사용
    public void showInput(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String input = req.getParameter("input");
        resp.getWriter().println("Input received: " + input);
    }
}
