from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class AgentMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool"] = "user"
    content: str = Field(min_length=1, max_length=4000)


class AgentRunRequest(BaseModel):
    session_id: str | None = None
    user_id: str | None = None
    messages: list[AgentMessage] = Field(min_length=1)
    context: dict[str, Any] = Field(default_factory=dict)


class AgentRunResponse(BaseModel):
    agent_name: str
    session_id: str
    summary: str
    reply: AgentMessage
    trace: list[str] = Field(default_factory=list)


class AgentProfileResponse(BaseModel):
    agent_name: str
    environment: str
    api_prefix: str
    capabilities: list[str]
