# backend

## 실행 방법

```bash
uv sync
uv run uvicorn src.main:app --reload
```

## 인증 API

- `GET /auth/github/login`: GitHub OAuth 로그인 URL 반환
- `GET /auth/github`: GitHub 로그인 페이지로 바로 리다이렉트
- `GET /auth/github/callback`: GitHub 로그인 완료 후 사용자 저장 및 access token 반환
- `GET /auth/me`: `Authorization: Bearer <token>` 으로 현재 사용자 조회

기본 DB는 프로젝트 루트의 `app.db` SQLite 파일로 생성됩니다.
