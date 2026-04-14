from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator

_GITHUB_REPO_URL_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.\-]+)/(?P<repo>[A-Za-z0-9_.\-]+?)(?:\.git)?$"
)


class GitHubCloneRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not _GITHUB_REPO_URL_RE.match(v):
            raise ValueError(
                "유효한 GitHub 레포지토리 URL이 아닙니다. "
                "https://github.com/owner/repo 형식으로 입력해주세요."
            )
        return v


class GitHubRunRequest(GitHubCloneRequest):
    session_id: str | None = None
    instructions: str | None = Field(default=None, max_length=4000)
    include_raw_analysis: bool = False
