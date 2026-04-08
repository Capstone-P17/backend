from datetime import datetime

from pydantic import BaseModel, ConfigDict


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    github_id: str
    github_login: str
    email: str | None
    display_name: str | None
    avatar_url: str | None
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class GithubLoginUrlResponse(BaseModel):
    authorization_url: str
