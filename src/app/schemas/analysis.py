from __future__ import annotations

from pydantic import BaseModel


class AnalyzeRepositoryRequest(BaseModel):
    url: str | None = None
