from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from src.app.core.config import get_settings
from src.app.db.base import Base

settings = get_settings()

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db_session() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def init_db() -> None:
    import src.app.models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    _ensure_analysis_results_user_id_column()


def _ensure_analysis_results_user_id_column() -> None:
    inspector = inspect(engine)
    if "analysis_results" not in inspector.get_table_names():
        return

    column_names = {column["name"] for column in inspector.get_columns("analysis_results")}
    if "user_id" in column_names:
        return

    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE analysis_results ADD COLUMN user_id INTEGER"))
