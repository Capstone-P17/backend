import java.security.*;

public class CryptoService {

    // 탐지 대상: MD5 사용 (충돌 취약점)
    public byte[] hashWithMD5(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(input.getBytes());
    }

    // 탐지 대상: SHA-1 사용 (충돌 취약점)
    public byte[] hashWithSHA1(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(input.getBytes());
    }

    // 탐지 대상: SHA1 (하이픈 없는 표기, 동일하게 취약)
    public byte[] hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA1");
        return digest.digest(password.getBytes());
    }

    // 탐지 제외: SHA-256 사용 (안전)
    public byte[] hashWithSHA256(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(input.getBytes());
    }

    // 탐지 제외: SHA-512 사용 (안전)
    public byte[] hashWithSHA512(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        return md.digest(input.getBytes());
    }
}
