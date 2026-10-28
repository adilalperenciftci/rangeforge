"""Claude via the Claude Code CLI (``claude -p``). Uses the operator's existing
subscription; no API key. One fresh, tool-less session per task."""

from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Any

from rangeforge.bench.backends.base import Backend, Completion


class ClaudeCliBackend(Backend):
    name = "claude-cli"

    @classmethod
    def default_model(cls) -> str:
        return "claude-sonnet-5-5"

    def complete(
        self, system: str, user: str, *, json_schema: dict[str, Any] | None = None
    ) -> Completion:
        cmd = [
            self.options.get("binary", "claude"),
            "-p",
            "--output-format",
            "json",
            "--model",
            self.model,
            "--system-prompt",
            system,
            "--tools",
            "",
            "--no-session-persistence",
            "--bare",
        ]
        if json_schema:
            cmd += ["--json-schema", json.dumps(json_schema)]
        env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE")}
        started = time.perf_counter()
        try:
            proc = subprocess.run(
                cmd,
                input=user,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=self.options.get("timeout", 300),
                env=env,
                check=False,
                shell=os.name == "nt",
            )
        except subprocess.TimeoutExpired:
            return Completion("", self.model, time.perf_counter() - started, error="timeout")
        latency = time.perf_counter() - started
        if proc.returncode != 0:
            return Completion(
                "",
                self.model,
                latency,
                error=f"exit {proc.returncode}: {proc.stderr.strip()[:300]}",
            )
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return Completion(proc.stdout, self.model, latency, error="non-json output")
        text = data.get("structured_output")
        text = json.dumps(text) if isinstance(text, dict) else str(data.get("result", ""))
        usage = data.get("usage", {}) or {}
        return Completion(
            text=text,
            model=self.model,
            latency_s=latency,
            input_tokens=(usage.get("input_tokens") or 0)
            + (usage.get("cache_read_input_tokens") or 0)
            + (usage.get("cache_creation_input_tokens") or 0),
            output_tokens=usage.get("output_tokens"),
            cost_usd=data.get("total_cost_usd"),
            raw={"session_id": data.get("session_id"), "stop_reason": data.get("stop_reason")},
        )
