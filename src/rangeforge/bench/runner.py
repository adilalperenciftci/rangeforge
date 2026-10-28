"""Run a backend over a task set, resumably, with bounded concurrency."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import orjson
from pydantic import BaseModel, ConfigDict, Field

from rangeforge.bench.backends.base import Backend
from rangeforge.bench.prompt import (
    ANSWER_SCHEMA,
    SYSTEM_PROMPT,
    Answer,
    looks_like_refusal,
    parse_answer,
    user_prompt,
)
from rangeforge.bench.tasks import TriageTask


class TaskResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    task_id: str
    backend: str
    model: str
    answer: Answer | None
    raw_text: str
    error: str | None = None
    refused: bool = False
    latency_s: float
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None
    at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


def run_one(backend: Backend, task: TriageTask, *, structured: bool = True) -> TaskResponse:
    completion = backend.complete(
        SYSTEM_PROMPT,
        user_prompt(task.to_prompt_dict()),
        json_schema=ANSWER_SCHEMA if structured else None,
    )
    answer = parse_answer(completion.text) if completion.ok else None
    refused = completion.ok and answer is None and looks_like_refusal(completion.text)
    error = completion.error
    if completion.ok and answer is None and not refused:
        error = "unparseable answer"
    return TaskResponse(
        task_id=task.id,
        backend=backend.name,
        model=backend.model,
        answer=answer,
        raw_text=completion.text[:4000],
        error=error,
        refused=refused,
        latency_s=completion.latency_s,
        input_tokens=completion.input_tokens,
        output_tokens=completion.output_tokens,
        cost_usd=completion.cost_usd,
    )


def load_responses(path: Path) -> dict[str, TaskResponse]:
    out: dict[str, TaskResponse] = {}
    if not path.exists():
        return out
    with path.open("rb") as fh:
        for line in fh:
            if line.strip():
                resp = TaskResponse.model_validate(orjson.loads(line))
                out[resp.task_id] = resp
    return out


def run_tasks(
    backend: Backend,
    tasks: Iterable[TriageTask],
    out: Path,
    *,
    concurrency: int = 2,
    retry_errors: bool = True,
    structured: bool = True,
    progress: Callable[[TaskResponse, int, int], None] | None = None,
) -> dict[str, TaskResponse]:
    """Append responses to ``out`` (JSONL). Tasks already answered are skipped,
    so an interrupted run resumes where it stopped."""
    out.parent.mkdir(parents=True, exist_ok=True)
    done = load_responses(out)
    todo = [t for t in tasks if t.id not in done or (retry_errors and done[t.id].error)]
    total = len(todo)
    if not todo:
        return done

    started = time.perf_counter()
    with out.open("ab") as fh, ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = {
            pool.submit(run_one, backend, task, structured=structured): task for task in todo
        }
        for i, future in enumerate(as_completed(futures), 1):
            resp = future.result()
            done[resp.task_id] = resp
            fh.write(orjson.dumps(resp.model_dump(mode="json")) + b"\n")
            fh.flush()
            if progress:
                progress(resp, i, total)
    _ = time.perf_counter() - started
    return done


def summarize_errors(responses: Iterable[TaskResponse]) -> dict[str, Any]:
    errors: dict[str, int] = {}
    refused = 0
    for resp in responses:
        if resp.refused:
            refused += 1
        if resp.error:
            key = resp.error.split(":")[0][:60]
            errors[key] = errors.get(key, 0) + 1
    return {"refused": refused, "errors": errors}
