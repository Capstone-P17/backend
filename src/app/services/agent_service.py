from __future__ import annotations

from uuid import uuid4

from src.app.core.config import Settings
from src.app.schemas.agent import AgentMessage, AgentRunRequest, AgentRunResponse


class AgentService:
    """Simple orchestration service that can be replaced by a real LLM adapter later."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def run(self, payload: AgentRunRequest) -> AgentRunResponse:
        session_id = payload.session_id or f"session-{uuid4().hex[:12]}"
        latest_user_message = next(
            (message for message in reversed(payload.messages) if message.role == "user"),
            None,
        )
        user_input = latest_user_message.content if latest_user_message else "No user input provided."

        trace = [
            "request_received",
            f"agent_selected:{self.settings.default_agent_name}",
            "context_prepared",
            "response_composed",
        ]

        reply = AgentMessage(
            role="assistant",
            content=self._build_reply(user_input=user_input, context=payload.context),
        )

        return AgentRunResponse(
            agent_name=self.settings.default_agent_name,
            session_id=session_id,
            summary="기본 에이전트 파이프라인으로 요청을 수신하고 응답을 구성했습니다.",
            reply=reply,
            trace=trace,
        )

    def _build_reply(self, user_input: str, context: dict[str, object]) -> str:
        context_keys = ", ".join(sorted(context.keys())) if context else "none"
        return (
            f"Processed request: {user_input}\n"
            f"Configured agent: {self.settings.default_agent_name}\n"
            f"Known context keys: {context_keys}\n"
            "Next step: connect this service to your real model client or tool executor."
        )
