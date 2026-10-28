from __future__ import annotations

from typing import Any

from rangeforge.bench.backends.base import Backend
from rangeforge.bench.backends.claude_cli import ClaudeCliBackend
from rangeforge.bench.backends.codex_cli import CodexCliBackend
from rangeforge.bench.backends.http_api import (
    AnthropicBackend,
    OllamaBackend,
    OpenAIBackend,
    ScriptedBackend,
)

_BACKENDS: dict[str, type[Backend]] = {
    cls.name: cls
    for cls in (
        ClaudeCliBackend,
        CodexCliBackend,
        AnthropicBackend,
        OpenAIBackend,
        OllamaBackend,
        ScriptedBackend,
    )
}


def available() -> list[str]:
    return sorted(_BACKENDS)


def create(name: str, model: str | None = None, **options: Any) -> Backend:
    try:
        cls = _BACKENDS[name]
    except KeyError as exc:
        raise ValueError(f"unknown backend {name!r}; available: {available()}") from exc
    return cls(model, **options)
