"""Direct HTTP backends: Anthropic Messages API, OpenAI Chat Completions, Ollama."""

from __future__ import annotations

import json
import os
import time
from typing import Any

import httpx

from rangeforge.bench.backends.base import Backend, Completion

# USD per million tokens (input, output); keep in sync with vendor pricing pages.
_PRICES: dict[str, tuple[float, float]] = {
    "claude-sonnet-5-5": (3.0, 15.0),
    "claude-opus-5-5": (15.0, 75.0),
    "claude-haiku-5-5": (0.8, 4.0),
}


def _cost(model: str, inp: int | None, out: int | None) -> float | None:
    price = _PRICES.get(model)
    if not price or inp is None or out is None:
        return None
    return (inp * price[0] + out * price[1]) / 1_000_000


class AnthropicBackend(Backend):
    name = "anthropic"

    @classmethod
    def default_model(cls) -> str:
        return "claude-sonnet-5-5"

    def complete(
        self, system: str, user: str, *, json_schema: dict[str, Any] | None = None
    ) -> Completion:
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            return Completion("", self.model, 0.0, error="ANTHROPIC_API_KEY not set")
        body: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.options.get("max_tokens", 1500),
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        started = time.perf_counter()
        try:
            resp = httpx.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
                json=body,
                timeout=self.options.get("timeout", 180),
            )
        except httpx.HTTPError as exc:
            return Completion("", self.model, time.perf_counter() - started, error=str(exc)[:200])
        latency = time.perf_counter() - started
        if resp.status_code != 200:
            return Completion(
                "", self.model, latency, error=f"HTTP {resp.status_code}: {resp.text[:200]}"
            )
        data = resp.json()
        text = "".join(
            block.get("text", "")
            for block in data.get("content", [])
            if block.get("type") == "text"
        )
        usage = data.get("usage", {})
        inp, out = usage.get("input_tokens"), usage.get("output_tokens")
        return Completion(
            text,
            self.model,
            latency,
            inp,
            out,
            _cost(self.model, inp, out),
            raw={"stop": data.get("stop_reason")},
        )


class OpenAIBackend(Backend):
    name = "openai"

    @classmethod
    def default_model(cls) -> str:
        return "gpt-5.5"

    def complete(
        self, system: str, user: str, *, json_schema: dict[str, Any] | None = None
    ) -> Completion:
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            return Completion("", self.model, 0.0, error="OPENAI_API_KEY not set")
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        if json_schema:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "triage", "schema": json_schema, "strict": False},
            }
        started = time.perf_counter()
        try:
            resp = httpx.post(
                self.options.get("base_url", "https://api.openai.com/v1") + "/chat/completions",
                headers={"Authorization": f"Bearer {key}"},
                json=body,
                timeout=self.options.get("timeout", 180),
            )
        except httpx.HTTPError as exc:
            return Completion("", self.model, time.perf_counter() - started, error=str(exc)[:200])
        latency = time.perf_counter() - started
        if resp.status_code != 200:
            return Completion(
                "", self.model, latency, error=f"HTTP {resp.status_code}: {resp.text[:200]}"
            )
        data = resp.json()
        text = data["choices"][0]["message"].get("content") or ""
        usage = data.get("usage", {})
        return Completion(
            text, self.model, latency, usage.get("prompt_tokens"), usage.get("completion_tokens")
        )


class OllamaBackend(Backend):
    name = "ollama"

    @classmethod
    def default_model(cls) -> str:
        return "llama3.1:8b"

    def complete(
        self, system: str, user: str, *, json_schema: dict[str, Any] | None = None
    ) -> Completion:
        base = self.options.get("base_url") or os.environ.get(
            "OLLAMA_HOST", "http://127.0.0.1:11434"
        )
        body: dict[str, Any] = {
            "model": self.model,
            "stream": False,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "options": {"temperature": 0},
        }
        if json_schema:
            body["format"] = json_schema
        started = time.perf_counter()
        try:
            resp = httpx.post(
                f"{base}/api/chat", json=body, timeout=self.options.get("timeout", 600)
            )
        except httpx.HTTPError as exc:
            return Completion("", self.model, time.perf_counter() - started, error=str(exc)[:200])
        latency = time.perf_counter() - started
        if resp.status_code != 200:
            return Completion(
                "", self.model, latency, error=f"HTTP {resp.status_code}: {resp.text[:200]}"
            )
        data = resp.json()
        text = data.get("message", {}).get("content", "")
        return Completion(
            text, self.model, latency, data.get("prompt_eval_count"), data.get("eval_count"), 0.0
        )


class ScriptedBackend(Backend):
    """Deterministic backend for tests and dry runs: echoes a fixed answer."""

    name = "scripted"

    @classmethod
    def default_model(cls) -> str:
        return "scripted"

    def complete(
        self, system: str, user: str, *, json_schema: dict[str, Any] | None = None
    ) -> Completion:
        answer = self.options.get("answer") or {
            "verdict": "malicious",
            "confidence": 0.5,
            "techniques": [],
            "tactic": None,
            "severity": "medium",
            "reasoning": "scripted",
            "actions": [],
        }
        return Completion(json.dumps(answer), self.model, 0.0, 10, 10, 0.0)
