# backend

## 실행 방법

```bash
uv sync
uv run uvicorn src.main:app --reload
```

## Docker 실행 방법

```bash
docker compose up --build
```

- `backend` : `8000` 포트로 실행됩
- `db` : `PostgreSQL 16` 기준으로 함께 실행
- `docker compose`로 실행하면 백엔드 컨테이너 내부의 `DATABASE_URL`이 `db`로 연결되도록 설정
