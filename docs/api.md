# API 요약

상세 요청/응답 스키마는 FastAPI Swagger UI에서 확인한다.

- Local Swagger UI: `http://localhost:8000/docs`
- OpenAPI JSON: `http://localhost:8000/openapi.json`

## Health / Capabilities

| Method | Path | 설명 |
|---|---|---|
| `GET` | `/` | 백엔드 실행 상태 확인 |
| `GET` | `/capabilities` | 현재 지원 detector, 공식 가이드 매핑, 분석 기능 범위 조회 |

## Auth

| Method | Path | 설명 |
|---|---|---|
| `GET` | `/auth/github/login` | GitHub OAuth 로그인 URL 발급 |
| `GET` | `/auth/github` | GitHub OAuth 로그인으로 redirect |
| `GET` | `/auth/github/callback` | GitHub OAuth callback 처리 및 HttpOnly JWT 쿠키 설정 |
| `GET` | `/auth/me` | 현재 로그인 사용자 조회 |
| `POST` | `/auth/logout` | 로그인 쿠키 제거 |

## Analysis

| Method | Path | 설명 |
|---|---|---|
| `POST` | `/analyze/file` | 단일 Java 파일 분석 |
| `POST` | `/analyze/archive` | ZIP/TAR 등 업로드 아카이브 분석 |
| `POST` | `/analyze/repository` | GitHub 저장소 URL 기반 동기 분석 |
| `POST` | `/analyze/repository/jobs` | GitHub 저장소 분석 비동기 작업 생성 |
| `GET` | `/analyze/jobs/{job_id}` | 저장소 분석 작업 상태 조회 |

### 정적 분석 엔진 경로

분석 API는 `AnalyzerService`를 통해 `src/app/services/static_analysis/runner.py`를 호출한다.
취약점별 탐지 로직은 `src/app/services/static_analysis/detectors/` 아래에 분리되어 있으며, `src/analyzer/test_samples/`는 실제 엔진이 아니라 테스트와 시연용 Java 샘플 경로다.

## Results

| Method | Path | 설명 |
|---|---|---|
| `GET` | `/result` | 최근 분석 결과 조회 |
| `GET` | `/result/{analysis_id}` | 특정 분석 결과 조회 |
| `GET` | `/result/{analysis_id}/findings/{finding_id}` | 개별 취약점 상세 조회 |
| `GET` | `/result/{analysis_id}/files/{file_id}` | 파일 단위 분석 결과 조회 |
| `GET` | `/results` | 분석 결과 목록 조회 |

## Report

| Method | Path | 설명 |
|---|---|---|
| `GET` | `/report/{analysis_id}` | PDF 분석 리포트 다운로드 |

## Agent

| Method | Path | 설명 |
|---|---|---|
| `GET` | `/agents/profile` | 보안 감사 agent 프로필 조회 |
| `POST` | `/agents/runs` | Agent 기반 분석 실행 |
| `POST` | `/agents/runs/file` | 파일 업로드 기반 Agent 분석 |
| `POST` | `/agents/runs/archive` | 압축 파일 기반 Agent 분석 |
| `POST` | `/agents/runs/repository` | GitHub 저장소 기반 Agent 분석 |

## 참고

- credential 기반 인증 API는 프론트엔드 요청에서 `credentials: "include"` 설정이 필요하다.
- GitHub OAuth를 사용하려면 `.env`에 `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_REDIRECT_URI`를 설정해야 한다.
- LLM 리포트 생성은 `OPENAI_API_KEY`가 설정된 경우에만 활성화된다.
