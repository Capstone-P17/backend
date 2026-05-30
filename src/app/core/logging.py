from __future__ import annotations

import logging
import sys
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from uuid import uuid4

from fastapi import Request, Response
from loguru import logger

from src.app.core.config import Settings


_CONFIGURED = False


class InterceptHandler(logging.Handler):
    """Route stdlib/uvicorn logs through Loguru so one format is used everywhere."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level: str | int = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = logging.currentframe(), 2
        while frame and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


def configure_logging(settings: Settings) -> None:
    """Configure Loguru sinks once per process.

    The default sink is stderr so uvicorn/docker logs remain visible. Optional file
    logging can be enabled through LOG_FILE_ENABLED without changing application code.
    """

    global _CONFIGURED
    if _CONFIGURED:
        return

    logger.remove()
    logger.configure(patcher=_ensure_log_context)
    logger.add(
        sys.stderr,
        level=settings.log_level,
        format=_log_format(settings.log_colorize),
        colorize=settings.log_colorize,
        backtrace=settings.log_backtrace,
        diagnose=settings.log_diagnose,
        enqueue=True,
    )

    if settings.log_file_enabled:
        log_path = Path(settings.log_file_path)
        if not log_path.is_absolute():
            log_path = settings.workspace_root / log_path
        log_path.parent.mkdir(parents=True, exist_ok=True)
        logger.add(
            log_path,
            level=settings.log_level,
            rotation=settings.log_file_rotation,
            retention=settings.log_file_retention,
            compression=settings.log_file_compression or None,
            serialize=settings.log_json,
            backtrace=settings.log_backtrace,
            diagnose=settings.log_diagnose,
            enqueue=True,
        )

    _install_stdlib_intercept(settings.log_level)
    _CONFIGURED = True
    logger.bind(component="logging").info(
        "logging_configured level={} file_enabled={} json={}",
        settings.log_level,
        settings.log_file_enabled,
        settings.log_json,
    )


async def log_request_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    request_id = request.headers.get("x-request-id") or uuid4().hex[:12]
    started = time.perf_counter()
    bound = logger.bind(
        component="http",
        request_id=request_id,
        method=request.method,
        path=request.url.path,
    )
    bound.info("request_started method={} path={}", request.method, request.url.path)
    try:
        response = await call_next(request)
    except Exception:
        elapsed_ms = (time.perf_counter() - started) * 1000
        bound.exception(
            "request_failed method={} path={} duration_ms={:.2f}",
            request.method,
            request.url.path,
            elapsed_ms,
        )
        raise

    elapsed_ms = (time.perf_counter() - started) * 1000
    response.headers["x-request-id"] = request_id
    bound.info(
        "request_finished method={} path={} status={} duration_ms={:.2f}",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    return response


def _ensure_log_context(record: dict) -> None:
    extra = record["extra"]
    extra.setdefault("component", "-")
    extra.setdefault("request_id", "-")


def _log_format(colorize: bool) -> str:
    plain = (
        "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level:<8} | {extra[request_id]} | "
        "{extra[component]} | {name}:{function}:{line} - {message}"
    )
    if not colorize:
        return plain
    return (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level:<8}</level> | "
        "<cyan>{extra[request_id]}</cyan> | "
        "<magenta>{extra[component]}</magenta> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
        "<level>{message}</level>"
    )


def _install_stdlib_intercept(level: str) -> None:
    logging.basicConfig(handlers=[InterceptHandler()], level=level, force=True)
    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access", "fastapi"):
        std_logger = logging.getLogger(logger_name)
        std_logger.handlers = [InterceptHandler()]
        std_logger.propagate = False
