# Official Benchmark Validation

이 문서는 Capstone-P17 백엔드 정적 분석기가 공식 취약점 샘플에서 현재 어디까지 탐지되는지 기록한다.
목표는 “오탐/미탐이 없다”는 식의 과장이 아니라, 공식 샘플 기준으로 확인된 탐지 범위와 한계를 회귀 테스트로 고정하는 것이다.

## 사용한 공식 소스

- OWASP BenchmarkJava: https://github.com/OWASP-Benchmark/BenchmarkJava
- OWASP Benchmark project page: https://owasp.org/www-project-benchmark/
- NIST SARD Juliet Java 1.3: https://samate.nist.gov/SARD/test-suites/111

Juliet Java 1.3 다운로드 파일은 NIST가 공개한 SHA-256과 일치한다.

```text
d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60
```

## 로컬 원본 위치

공식 원본은 repository에 넣지 않고 repo 밖에 둔다.

```text
/Users/imjihyeon/dev/security-benchmarks/
  OWASP-BenchmarkJava/
  Juliet-Java-1.3/
  juliet-java-1.3.zip
```

다른 위치에 두고 테스트하려면 다음 환경변수를 사용한다.

```bash
P17_BENCHMARK_ROOT=/path/to/security-benchmarks .venv/bin/python -m pytest tests/test_official_benchmark_cases.py
```

## 현재 검증 범위

| 구분 | 공식 소스 | 현재 결과 | 의미 |
| --- | --- | --- | --- |
| SQL Injection | OWASP BenchmarkJava | TP/TN 확인 | 취약 SQL 결합은 탐지하고, OWASP safe SQLi 샘플은 탐지하지 않는다. SQL 키워드는 문자열 리터럴 기준으로 판정해 주석/로그/일반 문자열 오탐 가능성을 줄인다. Spring MVC annotation 파라미터를 입력 source로 반영한다. |
| Weak Hash | OWASP BenchmarkJava, Juliet | TP/TN 확인 | MD2/MD5/SHA-1 계열 약한 해시 사용을 탐지한다. |
| Insecure Random | Juliet | TP 확인 | `java.util.Random` 기반 약한 난수 사용을 탐지한다. |
| Command Injection | OWASP BenchmarkJava | TP 확인 | `List`에 명령 인자를 쌓고 `ProcessBuilder.command(argList)`로 넘기는 흐름과, Controller 입력이 CommandExecutor를 거쳐 `Runtime.exec`로 전달되는 클래스/파일 경계 흐름을 탐지한다. |
| Path Traversal | OWASP BenchmarkJava | TP 확인 | 쿠키 값이 중간 변수에 저장되고 파일명 변수에 결합된 뒤 `FileInputStream`으로 전달되는 흐름과, Controller 입력이 Service/FileService 구현체를 거쳐 파일 접근 API로 전달되는 클래스/파일 경계 흐름을 탐지한다. Spring MVC annotation 파라미터를 입력 source로 반영한다. |
| XSS | OWASP BenchmarkJava, Juliet | TP 확인 | 분기 내부 `getParameter` 할당 후 후속 HTML 출력 sink로 전달되는 흐름, HTML 응답에서 header 값이 `format()` 출력으로 전달되는 흐름, Controller 입력이 Renderer/Service 구현체를 거쳐 HTML 반환값으로 출력되는 클래스/파일 경계 흐름을 탐지한다. Spring MVC annotation 파라미터를 입력 source로 반영한다. |
| Hardcoded Secret | Juliet | TP 확인 | generic 변수명 `data`에 문자열 리터럴이 할당된 뒤 `DriverManager.getConnection(..., data)` 비밀번호 인자로 사용되는 흐름을 탐지한다. |

현재 manifest는 공식 샘플 61개를 포함한다. OWASP BenchmarkJava 케이스는 `expectedresults-1.2.csv`의 ground truth를 기준으로 선별했고, Juliet 케이스는 CWE별 공식 테스트 케이스 구조를 기준으로 선별했다. 기준 결과는 다음과 같다.

| 결과 | 케이스 수 | 설명 |
|---|---:|---|
| TP | 34 | 공식 ground truth가 취약이고 현재 detector가 탐지한다. |
| TN | 27 | 공식 ground truth가 비취약이고 현재 detector가 탐지하지 않는다. |
| known FN | 0 | 현재 manifest 기준으로 의도적으로 남긴 known false negative는 없다. |
| FP | 0 | 현재 manifest에는 의도된 FP가 없다. |

## 해석 기준

- TP: 공식 ground truth가 취약이고 현재 detector가 탐지한다.
- TN: 공식 ground truth가 비취약이고 현재 detector가 탐지하지 않는다.
- known FN: 공식 ground truth는 취약이지만 현재 detector가 탐지하지 못한다. 발표/문서에서는 “현재 한계”로 명시한다.
- FP: 공식 ground truth가 비취약인데 현재 detector가 탐지한다. 현재 manifest에는 의도된 FP가 없다.

## 발표/로딩 화면에 쓸 수 있는 문구

```text
공식 OWASP BenchmarkJava와 NIST SARD Juliet Java 1.3 샘플 61개를 기준으로 회귀 테스트를 수행했습니다.
현재 SQL Injection, XSS, Weak Hash, Insecure Random, Command Injection, Path Traversal, Hardcoded Secret 일부 패턴은 공식 샘플에서 탐지 가능하며,
현재 manifest 기준으로 의도적으로 남긴 known false negative는 없습니다.
```

## 최근 개선 내역

- Spring MVC source: `@RequestParam`, `@PathVariable`, `@RequestHeader`, `@CookieValue`, `@RequestBody`, `@ModelAttribute`가 붙은 메서드 파라미터를 사용자 입력 source로 인식해 SQL Injection, XSS, Path Traversal 흐름에 연결하도록 개선했다.
- Spring MVC DTO source: `@RequestBody request`에서 파생되는 `request.getX()` getter와 `request.field` 필드 접근을 source 객체 기반 taint 흐름으로 유지해 SQL Injection, XSS, Path Traversal, Command Injection에 연결하도록 개선했다.
- SQL Injection framework sink: JPA/Hibernate `createQuery/createNativeQuery`, Spring `JdbcTemplate.query/update`, MyBatis annotation mapper의 `${...}` 문자열 치환을 SQL sink 모델에 추가했다. MyBatis `#{...}` 바인딩과 JPA `setParameter` 패턴은 안전 흐름으로 유지한다.
- SQL Injection MyBatis XML: XML mapper의 `select/insert/update/delete` statement에서 `${...}` 또는 `$name$` 문자열 치환을 탐지하고, `#{...}` 바인딩과 주석 처리된 statement는 제외하도록 보강했다.
- Command Injection: 프로젝트 단위 method index를 사용해 `Controller -> CommandExecutor -> Runtime.exec(...)`처럼 클래스/파일 경계를 넘는 명령 실행 흐름을 탐지하도록 개선했다.
- Command Injection: OWASP BenchmarkTest00006의 `request.getHeader(...) -> param -> argList.add(...) -> ProcessBuilder.command(argList)` 흐름을 탐지하도록 개선했다.
- Command Injection: `allowedCommands.contains(command)` 또는 `Set.of(...).contains(command)` 같은 허용 목록 검증이 확인된 명령 변수는 직접 실행 sink에서 제외해 오탐 가능성을 줄였다.
- File Upload: 프로젝트 단위 method index를 사용해 `Controller MultipartFile -> StorageService.save(file) -> transferTo/Files.copy`처럼 클래스/파일 경계를 넘는 업로드 저장 흐름을 탐지하도록 개선했다.
- Path Traversal: 프로젝트 단위 method index를 사용해 `Controller -> Service/FileService 구현체 -> FileInputStream`처럼 클래스/파일 경계를 넘는 경로 조작 흐름을 탐지하도록 개선했다.
- Path Traversal: OWASP BenchmarkTest00001의 `request.getCookies() -> Cookie.getValue() -> fileName -> FileInputStream` 흐름을 탐지하도록 개선했다.
- Path Traversal: `normalize()` 또는 `toRealPath()`로 정규화한 경로가 `startsWith(base)` 기준 디렉터리 검증을 거친 경우 파일 접근 sink에서 제외해 오탐 가능성을 줄였다.
- XSS: 프로젝트 단위 method index를 사용해 `Controller -> Renderer/Service 구현체 -> HTML 반환값 -> response.write(...)`처럼 클래스/파일 경계를 넘는 출력 흐름을 탐지하도록 개선했다.
- XSS: OWASP BenchmarkTest00013의 `request.getHeaders(...) -> param -> response.getWriter().format(...)` 흐름과 Juliet CWE83 14번의 branch assignment 후 HTML 출력 흐름을 탐지하도록 개선했다.
- Hardcoded Secret: Juliet CWE259 01번의 `data = "..." -> DriverManager.getConnection(..., data)` assignment 흐름을 탐지하도록 개선했다.
- Official manifest: OWASP BenchmarkJava와 NIST SARD Juliet Java 1.3 기반 회귀 테스트 manifest를 31개에서 61개로 확장했다. SQL Injection, XSS, Path Traversal, Command Injection, Weak Hash, Insecure Random, Hardcoded Secret의 추가 TP/TN 케이스를 포함한다.
- SQL Injection: 프로젝트 단위 method index와 필드/지역 변수 타입 추론을 사용해 `Controller -> Service -> DAO`처럼 클래스/파일 경계를 넘는 SQL Injection 흐름을 탐지하도록 개선했다.
- SQL Injection: interface 타입 필드가 유일한 `implements` 구현체로 연결되는 경우 구현체 메서드 summary를 사용해 파일 간 taint 흐름을 이어가도록 개선했다.
- SQL Injection: Spring 생성자 주입 형태의 `this.field = parameter` 대입과 `this.userService.findUser(...)` 필드 호출을 타입 해석에 반영하도록 개선했다.
- SQL Injection: 같은 이름의 메서드가 여러 개 있을 때 인자 개수로 overload를 구분해 잘못된 method summary가 섞이지 않도록 개선했다.
- SQL Injection: 같은 파일 안에서 caller의 오염된 인자가 callee 파라미터로 전달되고, callee 내부 SQL 생성/실행 sink까지 이어지는 1단계 inter-procedural 흐름을 탐지하도록 개선했다.
- SQL Injection: SQL 키워드 판정을 전체 AST 텍스트가 아니라 문자열 리터럴 기준으로 좁혀 주석, 로그 메시지, `selected` 같은 일반 단어로 인한 오탐 가능성을 줄였다.
- Repository analysis guardrail: ZIP slip, 절대 경로, symlink, 과도한 Java 파일 수/파일 크기 입력을 분석 전에 차단한다.

## 다음 개선 후보

1. Hardcoded Secret 정상 샘플과 File Upload 공식/준공식 샘플을 추가로 보강한다.
2. 여러 구현체가 존재하는 interface, 상속/다형성까지 inter-procedural taint 해석 범위를 확장한다.
