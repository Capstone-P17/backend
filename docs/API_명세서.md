# API 명세서 v1.0

**프로젝트**: P17 - LLM 기반 소스코드 보안취약점 점검 도구  
**작성일**: 2026-03-31  
**작성자**: 임지현  
**Base URL**: `http://localhost:8000`

---

## 1. 단일 파일 분석

**`POST /analyze/file`**

Java 소스 파일을 업로드하면 취약점을 분석하고 결과를 반환합니다.

### Request

| 항목 | 값 |
|------|-----|
| Content-Type | multipart/form-data |
| 파라미터 | file (File .java, 필수) |

### Request 예시

```bash
curl -X POST http://localhost:8000/analyze/file \
  -F "file=@UserDAO.java"
```

### Response (200 OK)

```json
{
  "analysis_result": {
    "repository": "",
    "analyzed_at": "2026-03-31T14:30:00",
    "language": "java",
    "files_analyzed": 1,
    "vulnerabilities": [
      {
        "id": "VULN-001",
        "type": "SQL_INJECTION",
        "severity": "HIGH",
        "file": "UserDAO.java",
        "line": 16,
        "function": "getUser",
        "code_snippet": "String query = ...",
        "call_chain": ["UserDAO.getUser", "stmt.executeQuery"],
        "description": ""
      }
    ],
    "call_graph": {
      "UserDAO.getUser": ["DriverManager.getConnection", "stmt.executeQuery"]
    },
    "summary": {
      "total_vulnerabilities": 1,
      "by_severity": {"HIGH": 1, "MEDIUM": 0, "LOW": 0},
      "by_type": {"SQL_INJECTION": 1, "XSS": 0, "HARDCODED_SECRET": 0},
      "score": {"overall": 85, "by_file": {"UserDAO.java": 85}}
    }
  }
}
```

### Error Response

| 상태코드 | 조건 | 응답 |
|----------|------|------|
| 400 | .java가 아닌 파일 | `{"error": "Java 파일만 분석 가능합니다"}` |
| 422 | 파일 미첨부 | `{"error": "파일을 첨부해주세요"}` |
| 500 | 파싱 실패 | `{"error": "파일 분석 중 오류 발생"}` |

---

## 2. GitHub 레포지토리 분석

**`POST /analyze/repo`**

GitHub 레포지토리 URL을 입력하면 클론 후 전체 Java 파일을 분석합니다.

### Request

| 항목 | 값 |
|------|-----|
| Content-Type | application/json |
| 파라미터 | url (string, 필수) |

### Request 예시

```bash
curl -X POST http://localhost:8000/analyze/repo \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/example/spring-app"}'
```

### Response (200 OK)

```json
{
  "analysis_result": {
    "repository": "https://github.com/example/spring-app",
    "analyzed_at": "2026-03-31T14:35:00",
    "language": "java",
    "files_analyzed": 8,
    "vulnerabilities": [],
    "call_graph": {},
    "summary": {
      "total_vulnerabilities": 0,
      "by_severity": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
      "by_type": {"SQL_INJECTION": 0, "XSS": 0, "HARDCODED_SECRET": 0},
      "score": {"overall": 100, "by_file": {}}
    }
  }
}
```

### Error Response

| 상태코드 | 조건 | 응답 |
|----------|------|------|
| 400 | URL 누락 또는 빈 값 | `{"error": "GitHub URL을 입력해주세요"}` |
| 400 | 유효하지 않은 URL | `{"error": "유효한 GitHub URL이 아닙니다"}` |
| 500 | 클론 실패 | `{"error": "레포지토리 클론 실패"}` |
| 500 | 분석 중 오류 | `{"error": "분석 중 오류 발생"}` |

---

## 3. 분석 결과 조회

**`GET /result`**

가장 최근 분석 결과를 반환합니다.

### Request 예시

```bash
curl http://localhost:8000/result
```

### Response (200 OK)

```json
{
  "analysis_result": {
    "repository": "https://github.com/example/spring-app",
    "analyzed_at": "2026-03-31T14:35:00",
    "language": "java",
    "files_analyzed": 8,
    "vulnerabilities": [],
    "call_graph": {},
    "summary": {}
  }
}
```

### Error Response

| 상태코드 | 조건 | 응답 |
|----------|------|------|
| 404 | 분석 이력 없음 | `{"error": "분석 결과가 없습니다"}` |

---

## 4. 헬스체크

**`GET /health`**

서버 상태를 확인합니다.

```bash
curl http://localhost:8000/health
```

```json
{
  "status": "ok",
  "version": "1.0.0"
}
```

---

## 공통 사항

**응답 형식**: 모든 응답은 `application/json`

### 취약점 타입 (type)

| 값 | 설명 |
|----|------|
| SQL_INJECTION | SQL 삽입 공격 |
| XSS | 크로스 사이트 스크립팅 |
| HARDCODED_SECRET | 하드코딩된 비밀번호/키/토큰 |

### 심각도 (severity)

| 값 | 점수 감점 | 대상 |
|----|-----------|------|
| HIGH | -15점 | SQL_INJECTION, XSS |
| MEDIUM | -5점 | HARDCODED_SECRET |
| LOW | -2점 | (향후 확장) |

### 보안 점수 (score)

100점 만점에서 취약점 심각도별 감점. 최소 0점.
