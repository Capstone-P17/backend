# Source / Sink / Sanitizer 모델

DoUSECURE의 정적 분석 엔진은 LLM이 취약점을 임의로 발견하는 방식이 아니라, Java AST에서 확인 가능한 rule-based 흐름을 먼저 탐지합니다.

탐지 규칙은 `/src/app/services/static_analysis/rules.py`에 중앙화되어 있으며, detector는 이 규칙표를 기준으로 입력 지점(source), 위험 지점(sink), 방어 지점(sanitizer)을 확인합니다.

## 공통 Source

HTTP 요청 입력과 Spring MVC 바인딩 파라미터를 주요 외부 입력으로 봅니다.

- Servlet API: `getParameter`, `getParameterValues`, `getHeader`, `getHeaders`, `getCookies`, `getQueryString`, `getRequestURI`, `getRequestURL`, `getPathInfo`
- Spring MVC: `@RequestParam`, `@PathVariable`, `@RequestHeader`, `@CookieValue`, `@RequestBody`, `@ModelAttribute`
- DTO/Object field: Spring MVC source 객체에서 파생되는 `request.getName()`, `request.name` 형태의 getter/field 접근도 같은 source 흐름으로 취급합니다.

## 취약점별 모델

| 취약점 | Source | Sink | Sanitizer / 안전 패턴 |
|---|---|---|---|
| SQL Injection | HTTP/Spring 입력 | `executeQuery`, `executeUpdate`, `execute`, `prepareStatement`, `createQuery`, `createNativeQuery`, `JdbcTemplate.query/update`, MyBatis annotation/XML mapper `${...}` | 바인딩 파라미터를 사용하는 `PreparedStatement`, JPA/Hibernate `setParameter`, MyBatis `#{...}` |
| XSS | HTTP/Spring 입력 | `print`, `println`, `write`, `append`, `format` 등 HTML 응답 출력 | `escapeHtml4`, `htmlEscape`, `encodeForHTML`, `sanitize` 등 출력 컨텍스트 이스케이프 |
| Path Traversal | HTTP/Spring 입력 | `File`, `FileInputStream`, `Paths.get`, `Path.of` 등 경로 생성/파일 접근 | `normalize`/`toRealPath`로 만든 경로가 `startsWith(base)` 기준 디렉터리 검증을 통과한 경우 |
| Command Injection | HTTP/Spring 입력 | `Runtime.exec`, `ProcessBuilder.command`, `new ProcessBuilder` | `allowedCommands.contains(command)`, `Set.of(...).contains(command)` 같은 명령 allowlist 검증 |
| Dangerous File Upload | `MultipartFile`, `Part`, `FileItem` | `transferTo`, `Files.copy`, `write` 등 파일 저장 | 확장자 allowlist, magic bytes, 크기/개수 제한, 서버 생성 파일명, 비공개 저장 경로, 실행권한 제거 |
| Weak Hash | `MessageDigest.getInstance(...)` | MD5/SHA-1 계열 또는 비밀번호 문맥의 일반 해시 | SHA-256 이상 또는 PBKDF2/bcrypt/scrypt/Argon2 |
| Insecure Random | `new Random()` | 토큰/세션/키/nonce 등 보안값 생성 문맥 | `SecureRandom` |

## 한계

- Source/Sink/Sanitizer 목록은 정적 규칙이므로 프레임워크별 커스텀 wrapper는 추가 모델링이 필요합니다.
- DTO getter/field 접근은 source 객체 기준으로 추적하지만, nested object graph 전체에 대한 정밀 points-to analysis는 아직 제한적입니다.
- MyBatis XML mapper는 `select/insert/update/delete` statement 내부의 `${...}`와 iBATIS식 `$name$` 문자열 치환을 탐지합니다. 동적 SQL의 모든 분기 조건을 정밀 해석하지는 않습니다.
- Sanitizer가 존재하더라도 출력/SQL/경로/명령 실행 등 실제 컨텍스트에 맞는지까지 완전 검증하지는 않습니다. 현재는 Path Traversal의 `normalize/toRealPath + startsWith(base)` 조합과 Command Injection의 allowlist `contains()` 조합처럼 AST에서 확인 가능한 안전 패턴을 우선 반영합니다.
- 파일/클래스 간 흐름은 method summary와 project index를 통해 일부 추적하지만, CodeQL/Sparrow 수준의 완전한 points-to/type analysis는 아닙니다.

따라서 현재 엔진은 "범용 완전 SAST"가 아니라, Java/Spring 코드에서 흔한 취약 패턴을 빠르게 선별하고 근거 중심 리포트를 제공하는 1차 스크리닝 도구입니다.
