import java.io.*;
import java.nio.file.*;
import java.util.*;
import javax.servlet.http.*;
import org.springframework.web.multipart.MultipartFile;

public class FileController {

    // 탐지 대상: new File(userInput) - 파일 직접 접근
    public void downloadFile(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String filename = req.getParameter("filename");
        File file = new File(filename);
        resp.getOutputStream().write(new FileInputStream(file).readAllBytes());
    }

    // 탐지 대상: new FileInputStream(userInput) - 파일 읽기
    public String readFile(HttpServletRequest req) throws IOException {
        String path = req.getParameter("path");
        FileInputStream fis = new FileInputStream(path);
        return new String(fis.readAllBytes());
    }

    // 탐지 대상: Paths.get(userInput) - NIO 경로 조작
    public byte[] readFilePath(HttpServletRequest req) throws IOException {
        String filepath = req.getParameter("file");
        Path p = Paths.get(filepath);
        return Files.readAllBytes(p);
    }

    // 탐지 대상: new FileReader(userInput) - 텍스트 파일 읽기
    public String readText(HttpServletRequest req) throws IOException {
        String name = req.getParameter("name");
        FileReader reader = new FileReader(name);
        char[] buf = new char[1024];
        reader.read(buf);
        return new String(buf);
    }

    // 탐지 제외: 하드코딩된 경로 (안전)
    public String readConfig() throws IOException {
        File file = new File("config/app.properties");
        return new String(new FileInputStream(file).readAllBytes());
    }

    // 탐지 제외: Paths.get에 상수 경로 (안전)
    public byte[] readLog() throws IOException {
        Path p = Paths.get("/var/log/app.log");
        return Files.readAllBytes(p);
    }

    // 탐지 제외: 사용자 입력을 파일 접근 없이 사용
    public void showFilename(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        resp.getWriter().println("Requested: " + name);
    }

    // 탐지 대상: 업로드 파일 형식 검증 없이 저장
    public void uploadProfile(MultipartFile file) throws IOException {
        Path target = Paths.get("uploads", "profile.tmp");
        file.transferTo(target);
    }

    // 탐지 대상: 업로드 스트림을 검증 없이 저장
    public void uploadDocument(MultipartFile file) throws IOException {
        Files.copy(file.getInputStream(), Paths.get("uploads", "document.tmp"));
    }

    // 탐지 제외: 확장자와 Content-Type 허용목록 검증 후 저장
    public void safeUpload(MultipartFile file) throws IOException {
        Set<String> allowedExtensions = Set.of("png", "jpg", "jpeg");
        Set<String> allowedContentTypes = Set.of("image/png", "image/jpeg");
        String originalName = file.getOriginalFilename();
        String ext = originalName.substring(originalName.lastIndexOf(".") + 1).toLowerCase(Locale.ROOT);
        String contentType = file.getContentType();

        if (!allowedExtensions.contains(ext) || !allowedContentTypes.contains(contentType)) {
            throw new SecurityException("Unsupported upload type");
        }

        Path target = Paths.get("uploads", "profile." + ext);
        file.transferTo(target);
    }
}
