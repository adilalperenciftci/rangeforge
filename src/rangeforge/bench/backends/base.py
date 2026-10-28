from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Completion:
    text: str
    model: str
    latency_s: float
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None
    error: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.error is None


class Backend(ABC):
    name: str

    def __init__(self, model: str | None = None, **options: Any) -> None:
        self.model = model or self.default_model()
        self.options = options

    @classmethod
    @abstractmethod
    def default_model(cls) -> str: ...

    @abstractmethod
    def complete(
        self, system: str, user: str, *, json_schema: dict[str, Any] | None = None
    ) -> Completion: ...

    def describe(self) -> str:
        return f"{self.name}:{self.model}"
