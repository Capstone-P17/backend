import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.springframework.web.multipart.MultipartFile;

public class UploadController {

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
