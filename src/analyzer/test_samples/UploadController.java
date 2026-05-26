import java.io.*;
import javax.imageio.ImageIO;
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

    // 탐지 대상: 확장자와 Content-Type만 검증하므로 파일 시그니쳐/크기/파일명 재생성 검증이 부족
    public void partialUpload(MultipartFile file) throws IOException {
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

    // 탐지 제외: 크기 제한, 확장자 allowlist, 파일 시그니쳐, 서버 생성 파일명을 함께 사용
    public void safeUpload(MultipartFile file) throws IOException {
        long maxUploadBytes = 1024 * 1024;
        if (file.getSize() > maxUploadBytes) {
            throw new SecurityException("Upload too large");
        }

        Set<String> allowedExtensions = Set.of("png", "jpg", "jpeg");
        String originalName = file.getOriginalFilename();
        String ext = originalName.substring(originalName.lastIndexOf(".") + 1).toLowerCase(Locale.ROOT);
        if (!allowedExtensions.contains(ext)) {
            throw new SecurityException("Unsupported upload type");
        }

        if (ImageIO.read(file.getInputStream()) == null) {
            throw new SecurityException("Invalid file signature");
        }

        String savedName = UUID.randomUUID().toString() + "." + ext;
        Path target = Paths.get("/var/app/private-files", savedName);
        file.transferTo(target);
    }
}
