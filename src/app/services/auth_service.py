from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.app.core.security import create_access_token
from src.app.models.user import User
from src.app.schemas.auth import TokenResponse


class InvalidGithubUserError(Exception):
    """Raised when GitHub user payload is missing required fields."""


class AuthService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def upsert_github_user(self, github_user: dict[str, object]) -> TokenResponse:
        github_id = str(github_user.get("id", "")).strip()
        github_login = str(github_user.get("login", "")).strip()
        if not github_id or not github_login:
            raise InvalidGithubUserError("GitHub 사용자 정보가 올바르지 않습니다")

        email_value = github_user.get("email")
        display_name_value = github_user.get("name")
        avatar_url_value = github_user.get("avatar_url")

        email = str(email_value).strip().lower() if isinstance(email_value, str) and email_value.strip() else None
        display_name = (
            str(display_name_value).strip() if isinstance(display_name_value, str) and display_name_value.strip() else None
        )
        avatar_url = (
            str(avatar_url_value).strip() if isinstance(avatar_url_value, str) and avatar_url_value.strip() else None
        )

        user = self.db.scalar(select(User).where(User.github_id == github_id))
        if user is None:
            user = User(
                github_id=github_id,
                github_login=github_login,
                email=email,
                display_name=display_name,
                avatar_url=avatar_url,
            )
            self.db.add(user)
        else:
            user.github_login = github_login
            user.email = email
            user.display_name = display_name
            user.avatar_url = avatar_url

        try:
            self.db.commit()
        except IntegrityError as exc:
            self.db.rollback()
            raise InvalidGithubUserError("GitHub 사용자 정보를 저장하는 중 충돌이 발생했습니다") from exc

        self.db.refresh(user)
        return TokenResponse(access_token=create_access_token(user.id), user=user)

    def get_user_by_id(self, user_id: int) -> User | None:
        return self.db.get(User, user_id)
