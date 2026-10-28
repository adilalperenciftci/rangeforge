"""OpenAI models via the Codex CLI (``codex exec``). Uses the operator's
ChatGPT/Codex login; no API key."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from rangeforge.bench.backends.base import Backend, Completion


class CodexCliBackend(Backend):
    name = "codex-cli"

    @classmethod
    def default_model(cls) -> str:
        return "gpt-5.5"

    def complete(
        self, system: str, user: str, *, json_schema: dict[str, Any] | None = None
    ) -> Completion:
        prompt = f"{system}\n\n{user}"
        schema_file: Path | None = None
        cmd = [
            self.options.get("binary", "codex"),
            "exec",
            "--json",
            "--ephemeral",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "-m",
            self.model,
        ]
        if json_schema:
            fd, name = tempfile.mkstemp(suffix=".json", prefix="rf-schema-")
            os.close(fd)
            schema_file = Path(name)
            schema_file.write_text(json.dumps(json_schema), encoding="utf-8")
            cmd += ["--output-schema", str(schema_file)]
        cmd.append(prompt)
        started = time.perf_counter()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=self.options.get("timeout", 300),
                check=False,
                shell=os.name == "nt",
            )
        except subprocess.TimeoutExpired:
            return Completion("", self.model, time.perf_counter() - started, error="timeout")
        finally:
            if schema_file:
                schema_file.unlink(missing_ok=True)
        latency = time.perf_counter() - started
        if proc.returncode != 0:
            return Completion(
                "",
                self.model,
                latency,
                error=f"exit {proc.returncode}: {proc.stderr.strip()[:300]}",
            )

        # --json streams one JSON event per line; the final agent message holds the answer.
        text = ""
        usage: dict[str, Any] = {}
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            item = event.get("item") or {}
            if event.get("type") == "item.completed" and item.get("type") == "agent_message":
                text = str(item.get("text", ""))
            if event.get("type") == "turn.completed":
                usage = event.get("usage", {}) or {}
        if not text:
            return Completion(
                proc.stdout[-2000:], self.model, latency, error="no agent message in output"
            )
        return Completion(
            text=text,
            model=self.model,
            latency_s=latency,
            input_tokens=usage.get("input_tokens"),
            output_tokens=usage.get("output_tokens"),
            cost_usd=None,
        )
