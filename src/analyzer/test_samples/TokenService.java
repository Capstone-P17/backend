import java.util.Random;
import java.security.SecureRandom;

public class TokenService {

    // 탐지 대상: new Random()을 token 변수에 사용 (보안 컨텍스트)
    public String generateToken() {
        Random random = new Random();
        return String.valueOf(random.nextLong());
    }

    // 탐지 대상: new Random()을 sessionId 생성에 사용
    public String createSession() {
        Random sessionRandom = new Random();
        int sessionId = sessionRandom.nextInt(Integer.MAX_VALUE);
        return "SESSION-" + sessionId;
    }

    // 탐지 제외: SecureRandom 사용 (안전)
    public String generateSecureToken() {
        SecureRandom sr = new SecureRandom();
        byte[] bytes = new byte[32];
        sr.nextBytes(bytes);
        return bytesToHex(bytes);
    }

    // 탐지 제외: 보안 컨텍스트가 아닌 일반 Random 사용 (게임/시뮬레이션)
    public int rollDice() {
        Random rng = new Random();
        return rng.nextInt(6) + 1;
    }

    // 탐지 제외: 보안 컨텍스트가 아닌 일반 Random (페이지 번호 등)
    public int getRandomPage() {
        Random pager = new Random();
        return pager.nextInt(100);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
