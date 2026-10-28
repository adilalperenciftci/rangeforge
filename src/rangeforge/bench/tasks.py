"""Build triage tasks from replayed, labelled telemetry.

Two populations:

* **malicious** - an alert that fired inside a labelled attack sample and whose
  rule is tagged with the sample's technique (or its parent). Ground truth is
  the sample's technique list and tactic.
* **benign** - an alert that fired on telemetry we collected from the lab while
  only administrative tooling (the collector itself, provisioning scripts,
  logons from the hypervisor host) was running. Ground truth: benign.

Alerts that fired in an attack sample but do not match its technique are
skipped: we cannot say with confidence whether they are noise or a real but
unlabelled side effect.
"""

from __future__ import annotations

import hashlib
import random
from collections import deque
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, Literal

import orjson
from pydantic import BaseModel, ConfigDict

from rangeforge.coverage.replay import technique_hit
from rangeforge.datasets.catalog import DatasetEntry, DatasetSource
from rangeforge.detect.alerts import Alert
from rangeforge.detect.engine import DetectionEngine
from rangeforge.schema.events import NormalizedEvent

Verdict = Literal["malicious", "benign"]

CONTEXT_FIELDS = (
    "EventID",
    "Channel",
    "Computer",
    "Image",
    "CommandLine",
    "ParentImage",
    "ParentCommandLine",
    "User",
    "IntegrityLevel",
    "TargetImage",
    "SourceImage",
    "GrantedAccess",
    "TargetFilename",
    "TargetObject",
    "Details",
    "ImageLoaded",
    "DestinationIp",
    "DestinationPort",
    "DestinationHostname",
    "QueryName",
    "TargetUserName",
    "SubjectUserName",
    "LogonType",
    "IpAddress",
    "ServiceName",
    "ServiceFileName",
    "TaskName",
    "ScriptBlockText",
    "ObjectName",
    "Properties",
    "AccessMask",
    "type",
    "key",
    "exe",
    "comm",
    "cwd",
    "syscall_name",
    "name",
    "uid",
    "auid",
)
MAX_FIELD_CHARS = 600


class ContextEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    time: str
    source: str
    event_id: str | None
    fields: dict[str, Any]
    is_trigger: bool = False


class GroundTruth(BaseModel):
    model_config = ConfigDict(frozen=True)

    verdict: Verdict
    techniques: tuple[str, ...] = ()
    tactic: str | None = None
    origin: str
    """Dataset sample path or live host/channel the alert came from."""


class TriageTask(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    alert: Alert
    context: list[ContextEvent]
    truth: GroundTruth

    def to_prompt_dict(self) -> dict[str, Any]:
        """What the model sees: never the ground truth, never dataset file names."""
        return {
            "alert": {
                "rule": self.alert.rule_title,
                "level": self.alert.level,
                "rule_tags": {
                    "techniques": list(self.alert.techniques),
                    "tactics": list(self.alert.tactics),
                },
                "host": self.alert.hostname,
                "time": self.alert.time.isoformat(),
                "summary": self.alert.summary,
                "fields": self.alert.fields,
            },
            "context_events": [
                {k: v for k, v in c.model_dump().items() if k != "source"} for c in self.context
            ],
        }


def _trim(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_FIELD_CHARS:
        return value[:MAX_FIELD_CHARS] + f"... [{len(value) - MAX_FIELD_CHARS} more chars]"
    return value


def _context_event(event: NormalizedEvent, *, trigger: bool = False) -> ContextEvent:
    fields = {
        k: _trim(event.native[k])
        for k in CONTEXT_FIELDS
        if event.native.get(k) not in (None, "", "-")
    }
    return ContextEvent(
        time=event.time.isoformat(),
        source=event.metadata.product,
        event_id=event.metadata.original_event_id,
        fields=fields,
        is_trigger=trigger,
    )


def _task_id(origin: str, alert: Alert) -> str:
    raw = f"{origin}|{alert.rule_id}|{alert.event_uid}|{alert.time.isoformat()}"
    return hashlib.sha1(raw.encode(), usedforsecurity=False).hexdigest()[:12]


def tasks_from_stream(
    events: Iterable[NormalizedEvent],
    engine: DetectionEngine,
    *,
    origin: str,
    truth_for: Any,
    before: int = 8,
    after: int = 4,
) -> Iterator[TriageTask]:
    """Run events through the engine and emit a task per alert with a
    window of surrounding events. ``truth_for(alert) -> GroundTruth | None``."""
    history: deque[NormalizedEvent] = deque(maxlen=before)
    pending: list[tuple[TriageTask, int]] = []  # task awaiting `after` more events

    def flush(task: TriageTask, extra: list[ContextEvent]) -> TriageTask:
        return task.model_copy(update={"context": task.context + extra})

    trailing: dict[str, list[ContextEvent]] = {}
    for event in events:
        # feed trailing context to pending tasks
        for task, remaining in list(pending):
            trailing.setdefault(task.id, []).append(_context_event(event))
            if remaining - 1 <= 0:
                pending.remove((task, remaining))
                yield flush(task, trailing.pop(task.id))
            else:
                pending[pending.index((task, remaining))] = (task, remaining - 1)

        for alert in engine.evaluate(event):
            truth = truth_for(alert)
            if truth is None:
                continue
            context = [_context_event(e) for e in history] + [_context_event(event, trigger=True)]
            task = TriageTask(id=_task_id(origin, alert), alert=alert, context=context, truth=truth)
            pending.append((task, after))
        history.append(event)

    for task, _ in pending:
        yield flush(task, trailing.pop(task.id, []))


def build_tasks(
    source: DatasetSource,
    engine: DetectionEngine,
    *,
    entries: Iterable[DatasetEntry] | None = None,
    benign_events: Iterable[NormalizedEvent] | None = None,
    benign_origin: str = "lab-admin-activity",
    max_per_sample: int = 3,
    seed: int = 7,
) -> list[TriageTask]:
    rng = random.Random(seed)  # noqa: S311 - deterministic sampling, not security
    tasks: list[TriageTask] = []

    for entry in entries if entries is not None else source.entries():
        if not entry.labels:
            continue
        labels = set(entry.labels)

        def truth_for(
            alert: Alert, _labels: set[str] = labels, _entry: DatasetEntry = entry
        ) -> GroundTruth | None:
            fired = set(alert.techniques)
            if not fired or not any(technique_hit(label, fired) for label in _labels):
                return None
            return GroundTruth(
                verdict="malicious",
                techniques=tuple(sorted(_labels)),
                tactic=_entry.tactic,
                origin=_entry.path,
            )

        sample_tasks = list(
            tasks_from_stream(source.replay(entry), engine, origin=entry.path, truth_for=truth_for)
        )
        # keep a bounded, deterministic subset per sample so one noisy sample
        # does not dominate the benchmark
        seen_rules: dict[str, TriageTask] = {}
        for task in sample_tasks:
            seen_rules.setdefault(task.alert.rule_id, task)
        chosen = list(seen_rules.values())
        rng.shuffle(chosen)
        tasks.extend(chosen[:max_per_sample])

    if benign_events is not None:

        def benign_truth(alert: Alert) -> GroundTruth:
            return GroundTruth(verdict="benign", origin=benign_origin)

        benign = list(
            tasks_from_stream(benign_events, engine, origin=benign_origin, truth_for=benign_truth)
        )
        by_rule: dict[str, list[TriageTask]] = {}
        for task in benign:
            by_rule.setdefault(task.alert.rule_id, []).append(task)
        for group in by_rule.values():
            rng.shuffle(group)
            tasks.extend(group[:max_per_sample])

    rng.shuffle(tasks)
    return tasks


def save_tasks(tasks: Iterable[TriageTask], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("wb") as fh:
        for task in tasks:
            fh.write(orjson.dumps(task.model_dump(mode="json")) + b"\n")
            n += 1
    return n


def load_tasks(path: Path) -> list[TriageTask]:
    out: list[TriageTask] = []
    with path.open("rb") as fh:
        for line in fh:
            if line.strip():
                out.append(TriageTask.model_validate(orjson.loads(line)))
    return out
