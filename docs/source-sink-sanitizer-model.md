# Source / Sink / Sanitizer 모델

DoUSECURE의 정적 분석 엔진은 LLM이 취약점을 임의로 발견하는 방식이 아니라, Java AST에서 확인 가능한 rule-based 흐름을 먼저 탐지합니다.

주요 탐지 규칙은 `/src/app/services/static_analysis/rules.py`에 중앙화되어 있으며, detector는 이 규칙표를 기준으로 입력 지점(source), 위험 지점(sink), 방어 지점(sanitizer)을 확인합니다. 일부 detector는 코드 구조상 추가 휴리스틱을 함께 사용하지만, 문서의 기준표와 공통 룰 카탈로그가 어긋나지 않도록 유지합니다.

## 공통 Source

HTTP 요청 입력과 Spring MVC 바인딩 파라미터를 주요 외부 입력으로 봅니다.

- Servlet API: `getParameter`, `getParameterValues`, `getHeader`, `getHeaders`, `getCookies`, `getQueryString`, `getRequestURI`, `getRequestURL`, `getPathInfo`
- Spring MVC: `@RequestParam`, `@PathVariable`, `@RequestHeader`, `@CookieValue`, `@RequestBody`, `@ModelAttribute`
- DTO/Object field: Spring MVC source 객체에서 파생되는 `request.getName()`, `request.name` 형태의 getter/field 접근도 같은 source 흐름으로 취급합니다.

## 취약점별 모델

| 취약점 | Source | Sink | Sanitizer / 안전 패턴 |
|---|---|---|---|
| SQL Injection | HTTP/Spring 입력, Spring MVC DTO getter/field | `executeQuery`, `executeUpdate`, `execute`, `executeLargeUpdate`, `executeBatch`, `prepareStatement`, `createQuery`, `createNativeQuery`, `createSQLQuery`, `createMutationQuery`, `newQuery`, `JdbcTemplate.query/update` 계열, MyBatis annotation/XML mapper `${...}` 또는 `$name$` | 바인딩 파라미터를 사용하는 `PreparedStatement`, JPA/Hibernate `setParameter`, MyBatis `#{...}` |
| XSS | HTTP/Spring 입력, Spring MVC DTO getter/field | `print`, `println`, `write`, `append`, `format` 등 HTML 응답 출력 또는 HTML 반환값 출력 흐름 | `escapeHtml`, `escapeHtml4`, `htmlEscape`, `encodeForHTML`, `forHtml`, `clean`, `sanitize` 등 출력 컨텍스트 이스케이프 |
| Hardcoded Secret | 문자열 리터럴, API key/token/key 형식 값, 민감 키워드 변수명 | 소스 코드 또는 할당문에 남는 비밀번호/토큰/API key/credential/key 문자열, `getConnection`, `authenticate`, `setPassword`, `PasswordAuthentication` 등 민감 사용처 | `${...}`, `%...%` 설정 placeholder, `System.getenv(...)`, 외부 설정/시크릿 매니저 주입 |
| Path Traversal | HTTP/Spring 입력, Spring MVC DTO getter/field | `File`, `FileInputStream`, `FileOutputStream`, `FileReader`, `FileWriter`, `RandomAccessFile`, `Paths.get`, `Path.of` 등 경로 생성/파일 접근 | `normalize`/`toRealPath`로 만든 경로가 `startsWith(base)` 기준 디렉터리 검증을 통과한 경우 |
| Command Injection | HTTP/Spring 입력, Spring MVC DTO getter/field | `Runtime.exec`, `ProcessBuilder.command`, `new ProcessBuilder` | `allowedCommands.contains(command)`, `Set.of(...).contains(command)`, `List.of(...).contains(command)` 같은 명령 allowlist 검증 |
| Dangerous File Upload | `MultipartFile`, `Part`, `FileItem` | `transferTo`, `Files.copy`, `write`, `copyInputStreamToFile`, `copyToFile` 등 파일 저장 | 확장자 allowlist, magic bytes, 크기/개수 제한, 서버 생성 파일명, 비공개 저장 경로, 실행권한 제거 |
| Weak Hash | `MessageDigest.getInstance(...)` 알고리즘 문자열과 사용 문맥 | MD2/MD4/MD5/SHA-1 계열 또는 비밀번호 문맥의 일반 해시 | SHA-256 이상 일반 해시, 비밀번호 저장 문맥의 PBKDF2/bcrypt/scrypt/Argon2 및 salt/KDF 사용 |
| Insecure Random | `new Random()` 또는 보안 문맥 변수/메서드명 | 토큰/세션/키/nonce/salt/password/auth/OTP/CSRF 등 보안값 생성 문맥 | `SecureRandom` |

## 한계

- Source/Sink/Sanitizer 목록은 정적 규칙이므로 프레임워크별 커스텀 wrapper는 추가 모델링이 필요합니다.
- DTO getter/field 접근은 source 객체 기준으로 추적하지만, nested object graph 전체에 대한 정밀 points-to analysis는 아직 제한적입니다.
- MyBatis XML mapper는 `select/insert/update/delete` statement 내부의 `${...}`와 iBATIS식 `$name$` 문자열 치환을 탐지합니다. 동적 SQL의 모든 분기 조건을 정밀 해석하지는 않습니다.
- Hardcoded Secret은 사용처가 확인되지 않아도 소스에 민감 문자열이 남는 경우를 탐지합니다. 단, placeholder/test/dummy 값은 낮은 신뢰도로 분류하거나 설정 placeholder로 제외합니다.
- Sanitizer가 존재하더라도 출력/SQL/경로/명령 실행 등 실제 컨텍스트에 맞는지까지 완전 검증하지는 않습니다. 현재는 Path Traversal의 `normalize/toRealPath + startsWith(base)` 조합과 Command Injection의 allowlist `contains()` 조합처럼 AST에서 확인 가능한 안전 패턴을 우선 반영합니다.
- 파일/클래스 간 흐름은 method summary와 project index를 통해 일부 추적하지만, CodeQL/Sparrow 수준의 완전한 points-to/type analysis는 아닙니다.

따라서 현재 엔진은 "범용 완전 SAST"가 아니라, Java/Spring 코드에서 흔한 취약 패턴을 빠르게 선별하고 근거 중심 리포트를 제공하는 1차 스크리닝 도구입니다.
