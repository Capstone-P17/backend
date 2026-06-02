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
| SQL Injection | OWASP BenchmarkJava | TP/TN 확인 | 취약 SQL 결합은 탐지하고, OWASP safe SQLi 샘플은 탐지하지 않는다. SQL 키워드는 문자열 리터럴 기준으로 판정해 주석/로그/일반 문자열 오탐 가능성을 줄인다. |
| Weak Hash | OWASP BenchmarkJava, Juliet | TP/TN 확인 | MD2/MD5/SHA-1 계열 약한 해시 사용을 탐지한다. |
| Insecure Random | Juliet | TP 확인 | `java.util.Random` 기반 약한 난수 사용을 탐지한다. |
| Command Injection | OWASP BenchmarkJava | TP 확인 | `List`에 명령 인자를 쌓고 `ProcessBuilder.command(argList)`로 넘기는 흐름을 탐지한다. |
| Path Traversal | OWASP BenchmarkJava | TP 확인 | 쿠키 값이 중간 변수에 저장되고 파일명 변수에 결합된 뒤 `FileInputStream`으로 전달되는 흐름을 탐지한다. |
| XSS | OWASP BenchmarkJava, Juliet | known FN | 분기 내부 할당 후 다른 분기에서 출력되는 흐름은 현재 XSS tracker가 유지하지 못한다. |
| Hardcoded Secret | Juliet | known FN | generic 변수명 `data`에 할당된 하드코딩 비밀번호가 이후 비밀번호 인자로 쓰이는 흐름은 아직 탐지하지 못한다. |

현재 manifest 기준 결과는 다음과 같다.

| 결과 | 케이스 수 | 설명 |
|---|---:|---|
| TP | 6 | 공식 ground truth가 취약이고 현재 detector가 탐지한다. |
| TN | 3 | 공식 ground truth가 비취약이고 현재 detector가 탐지하지 않는다. |
| known FN | 3 | 공식 ground truth는 취약이지만 현재 detector가 탐지하지 못한다. |
| FP | 0 | 현재 manifest에는 의도된 FP가 없다. |

## 해석 기준

- TP: 공식 ground truth가 취약이고 현재 detector가 탐지한다.
- TN: 공식 ground truth가 비취약이고 현재 detector가 탐지하지 않는다.
- known FN: 공식 ground truth는 취약이지만 현재 detector가 탐지하지 못한다. 발표/문서에서는 “현재 한계”로 명시한다.
- FP: 공식 ground truth가 비취약인데 현재 detector가 탐지한다. 현재 manifest에는 의도된 FP가 없다.

## 발표/로딩 화면에 쓸 수 있는 문구

```text
공식 OWASP BenchmarkJava와 NIST SARD Juliet Java 1.3 샘플 일부를 기준으로 회귀 테스트를 수행했습니다.
현재 SQL Injection, Weak Hash, Insecure Random, Command Injection, Path Traversal 일부 패턴은 공식 샘플에서 탐지 가능하며,
분기/메서드 간 데이터 흐름이 더 필요한 XSS, Hardcoded Secret 일부 샘플은 known false negative로 관리하고 있습니다.
```

## 최근 개선 내역

- Command Injection: OWASP BenchmarkTest00006의 `request.getHeader(...) -> param -> argList.add(...) -> ProcessBuilder.command(argList)` 흐름을 탐지하도록 개선했다.
- Path Traversal: OWASP BenchmarkTest00001의 `request.getCookies() -> Cookie.getValue() -> fileName -> FileInputStream` 흐름을 탐지하도록 개선했다.
- SQL Injection: SQL 키워드 판정을 전체 AST 텍스트가 아니라 문자열 리터럴 기준으로 좁혀 주석, 로그 메시지, `selected` 같은 일반 단어로 인한 오탐 가능성을 줄였다.
- Repository analysis guardrail: ZIP slip, 절대 경로, symlink, 과도한 Java 파일 수/파일 크기 입력을 분석 전에 차단한다.

## 다음 개선 후보

1. XSS: 분기 내부 assignment 이후 후속 sink에서 taint가 유지되도록 method-level flow 개선
2. Hardcoded Secret: declaration뿐 아니라 assignment expression의 문자열 리터럴과 sink 사용처를 함께 추적
