from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DetectorMetadata:
    cwe: str
    severity: str
    guide_source: str
    guide_category: str
    guide_item: str
    description: str
    recommendation: str
    safe_example: str
    confidence: str
    confidence_reason: str


GUIDE_SOURCE = "행정안전부 「소프트웨어 보안약점 진단가이드(2019.6. 개정)」"


DETECTOR_METADATA: dict[str, DetectorMetadata] = {
    "SQL_INJECTION": DetectorMetadata(
        cwe="CWE-89",
        severity="HIGH",
        guide_source=GUIDE_SOURCE,
        guide_category="입력데이터 검증 및 표현",
        guide_item="SQL 삽입",
        description="사용자 입력이 SQL 문자열에 직접 결합되어 쿼리 구조가 변조될 수 있습니다.",
        recommendation="PreparedStatement와 바인딩 파라미터를 사용하고, SQL 문자열에 사용자 입력을 직접 연결하지 마세요.",
        safe_example='PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nps.setString(1, userId);',
        confidence="HIGH",
        confidence_reason="외부 입력 또는 메서드 파라미터가 SQL 문자열 생성 지점을 거쳐 SQL 실행 API까지 도달하는 흐름을 확인했기 때문에 HIGH로 판단했습니다.",
    ),
    "XSS": DetectorMetadata(
        cwe="CWE-79",
        severity="HIGH",
        guide_source=GUIDE_SOURCE,
        guide_category="입력데이터 검증 및 표현",
        guide_item="크로스사이트 스크립트",
        description="검증되지 않은 사용자 입력이 HTML 응답에 직접 출력되어 브라우저에서 스크립트가 실행될 수 있습니다.",
        recommendation="출력 컨텍스트에 맞게 HTML 이스케이프를 적용하고 템플릿 엔진의 자동 이스케이프 기능을 사용하세요.",
        safe_example="String safe = StringEscapeUtils.escapeHtml4(userInput);\nresp.getWriter().println(safe);",
        confidence="HIGH",
        confidence_reason="사용자 입력이 HTML 응답 출력 지점까지 전달되고, 탐지 가능한 HTML 이스케이프 또는 sanitizer 호출이 확인되지 않았기 때문에 HIGH로 판단했습니다.",
    ),
    "HARDCODED_SECRET": DetectorMetadata(
        cwe="CWE-798",
        severity="MEDIUM",
        guide_source=GUIDE_SOURCE,
        guide_category="보안기능",
        guide_item="하드코드된 비밀번호 / 하드코드된 암호화 키",
        description="소스 코드에 비밀번호, 토큰, API 키 등 인증 정보가 하드코딩되어 노출될 수 있습니다.",
        recommendation="비밀 값은 환경 변수, 시크릿 매니저, 안전한 설정 저장소에서 주입하고 저장소 이력의 노출 여부를 점검하세요.",
        safe_example='String apiKey = System.getenv("API_KEY");',
        confidence="MEDIUM",
        confidence_reason="하드코딩된 문자열이 민감 호출에 사용되는 흐름은 확인했지만, 실제 비밀값의 유효성이나 운영 환경 노출 범위는 정적 분석만으로 확정할 수 없어 MEDIUM으로 판단했습니다.",
    ),
    "PATH_TRAVERSAL": DetectorMetadata(
        cwe="CWE-22",
        severity="HIGH",
        guide_source=GUIDE_SOURCE,
        guide_category="입력데이터 검증 및 표현",
        guide_item="경로 조작 및 자원 삽입",
        description="사용자 입력이 파일 경로 생성에 직접 사용되어 허용된 디렉터리 밖의 파일에 접근할 수 있습니다.",
        recommendation="입력 파일명을 허용 목록으로 검증하고 정규화된 경로가 기준 디렉터리 내부인지 확인하세요.",
        safe_example="Path base = Paths.get(UPLOAD_DIR).toRealPath();\nPath target = base.resolve(fileName).normalize();\nif (!target.startsWith(base)) throw new SecurityException();",
        confidence="HIGH",
        confidence_reason="사용자 입력이 경로 생성 또는 파일 접근 API로 직접 전달되는 패턴을 확인했기 때문에 HIGH로 판단했습니다.",
    ),
    "COMMAND_INJECTION": DetectorMetadata(
        cwe="CWE-78",
        severity="CRITICAL",
        guide_source=GUIDE_SOURCE,
        guide_category="입력데이터 검증 및 표현",
        guide_item="운영체제 명령어 삽입",
        description="사용자 입력이 운영체제 명령 실행에 전달되어 임의 명령 실행으로 이어질 수 있습니다.",
        recommendation="쉘 명령 문자열 조합을 피하고, 허용된 명령/인자만 ProcessBuilder에 분리된 인자로 전달하세요.",
        safe_example='ProcessBuilder pb = new ProcessBuilder("/usr/bin/convert", safeInputFile, safeOutputFile);',
        confidence="HIGH",
        confidence_reason="사용자 입력이 운영체제 명령 실행 API에 전달되는 위험한 호출 흐름을 확인했기 때문에 HIGH로 판단했습니다.",
    ),
    "INSECURE_RANDOM": DetectorMetadata(
        cwe="CWE-338",
        severity="MEDIUM",
        guide_source=GUIDE_SOURCE,
        guide_category="보안기능",
        guide_item="적절하지 않은 난수값 사용",
        description="보안 토큰이나 키 생성에 예측 가능한 난수 생성기가 사용되어 값을 추측당할 수 있습니다.",
        recommendation="인증 토큰, 세션 ID, 키, nonce 등 보안 값에는 java.security.SecureRandom을 사용하세요.",
        safe_example="SecureRandom random = new SecureRandom();\nbyte[] token = new byte[32];\nrandom.nextBytes(token);",
        confidence="MEDIUM",
        confidence_reason="예측 가능한 난수 생성기 사용은 확인했지만 해당 값이 실제 보안 토큰이나 키로 쓰이는 전체 맥락은 제한적으로만 확인되므로 MEDIUM으로 판단했습니다.",
    ),
    "WEAK_HASH": DetectorMetadata(
        cwe="CWE-328",
        severity="MEDIUM",
        guide_source=GUIDE_SOURCE,
        guide_category="보안기능",
        guide_item="취약한 암호화 알고리즘 사용 / 솔트 없이 일방향 해시 함수 사용",
        description="MD5 또는 SHA-1 같은 약한 해시 알고리즘은 충돌 공격에 취약하여 무결성/인증 용도에 부적합합니다.",
        recommendation="일반 해시는 SHA-256 이상을 사용하고, 비밀번호 저장에는 bcrypt, scrypt, Argon2 같은 전용 KDF를 사용하세요.",
        safe_example='MessageDigest digest = MessageDigest.getInstance("SHA-256");',
        confidence="HIGH",
        confidence_reason="MD5 또는 SHA-1처럼 알려진 취약 해시 알고리즘 호출이 코드에서 직접 확인되었기 때문에 HIGH로 판단했습니다.",
    ),
    "DANGEROUS_FILE_UPLOAD": DetectorMetadata(
        cwe="CWE-434",
        severity="HIGH",
        guide_source=GUIDE_SOURCE,
        guide_category="입력데이터 검증 및 표현",
        guide_item="위험한 형식 파일 업로드",
        description="업로드 파일의 확장자 또는 Content-Type을 허용목록으로 제한하지 않고 서버에 저장하여, 실행 가능한 파일이나 악성 파일이 업로드될 수 있습니다.",
        recommendation="업로드 전에 허용 확장자와 Content-Type을 allowlist로 검증하고, 저장 경로와 파일명을 서버가 통제하는 값으로 재생성하세요.",
        safe_example=(
            'Set<String> allowedExtensions = Set.of("jpg", "png", "pdf");\n'
            'String ext = FilenameUtils.getExtension(file.getOriginalFilename()).toLowerCase(Locale.ROOT);\n'
            "if (!allowedExtensions.contains(ext)) throw new SecurityException();\n"
            "file.transferTo(targetPath);"
        ),
        confidence="HIGH",
        confidence_reason="업로드 파일 객체가 파일 저장 API로 전달되고, 저장 전에 확장자 또는 Content-Type 허용목록 검증이 확인되지 않았기 때문에 HIGH로 판단했습니다.",
    ),
}


def enrich_finding(finding: dict) -> dict:
    metadata = DETECTOR_METADATA.get(finding.get("type"))
    if metadata is None:
        return finding

    enriched = dict(finding)
    enriched.setdefault("cwe", metadata.cwe)
    enriched.setdefault("guide_source", metadata.guide_source)
    enriched.setdefault("guide_category", metadata.guide_category)
    enriched.setdefault("guide_item", metadata.guide_item)
    enriched["description"] = enriched.get("description") or metadata.description
    enriched.setdefault("evidence", "")
    enriched.setdefault("recommendation", metadata.recommendation)
    enriched.setdefault("safe_example", metadata.safe_example)
    enriched.setdefault("confidence", metadata.confidence)
    enriched.setdefault("confidence_reason", metadata.confidence_reason)
    return enriched
