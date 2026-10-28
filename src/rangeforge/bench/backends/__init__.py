"""Model backends. Every backend turns (system, user) into a Completion."""

from __future__ import annotations

from rangeforge.bench.backends.base import Backend, Completion
from rangeforge.bench.backends.registry import available, create

__all__ = ["Backend", "Completion", "available", "create"]
