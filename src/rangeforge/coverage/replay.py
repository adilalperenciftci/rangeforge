"""Replay labelled dataset samples through the detection engine and record,
per sample, which rules fired and whether the ground-truth technique was hit."""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Callable, Iterable
from pathlib import Path

import orjson
from pydantic import BaseModel, ConfigDict, Field

from rangeforge.datasets.catalog import DatasetEntry, DatasetSource
from rangeforge.detect.alerts import Alert
from rangeforge.detect.engine import DetectionEngine


def technique_hit(label: str, fired: set[str]) -> bool:
    """A label counts as detected when a fired rule is tagged with the same
    technique, with its parent technique, or with one of its sub-techniques.
    Sibling sub-techniques (T1003.001 vs T1003.002) do not count."""
    if label in fired:
        return True
    parent = label.split(".")[0]
    if "." in label and parent in fired:
        return True
    return any(t.startswith(label + ".") for t in fired)


class SampleResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    dataset: str
    path: str
    tactic: str | None
    labels: tuple[str, ...]
    events: int
    alerts: int
    rules_fired: dict[str, int] = Field(default_factory=dict)
    """rule title -> hit count."""
    techniques_fired: dict[str, int] = Field(default_factory=dict)
    """ATT&CK technique id (from rule tags) -> hit count."""
    seconds: float
    error: str | None = None

    @property
    def detected_any(self) -> bool:
        return self.alerts > 0

    @property
    def detected_labelled(self) -> bool:
        """True if at least one fired rule is tagged with a ground-truth technique
        (or its parent technique) of this sample."""
        fired = set(self.techniques_fired)
        return any(technique_hit(label, fired) for label in self.labels)


class ReplayResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    rules_loaded: int
    rules_failed: int
    samples: list[SampleResult]
    seconds: float

    @property
    def events(self) -> int:
        return sum(s.events for s in self.samples)

    def write_jsonl(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as fh:
            for sample in self.samples:
                fh.write(orjson.dumps(sample.model_dump(mode="json")) + b"\n")


def _replay_one(
    source: DatasetSource,
    entry: DatasetEntry,
    engine: DetectionEngine,
    alert_sink: Callable[[Alert], None] | None,
) -> SampleResult:
    started = time.perf_counter()
    rules: Counter[str] = Counter()
    techniques: Counter[str] = Counter()
    events = 0
    alerts = 0
    error: str | None = None
    try:
        for event in source.replay(entry):
            events += 1
            for alert in engine.evaluate(event):
                alerts += 1
                rules[alert.rule_title] += 1
                for technique in alert.techniques:
                    techniques[technique] += 1
                if alert_sink:
                    alert_sink(alert)
    except Exception as exc:  # corrupt sample must not abort the run
        error = f"{type(exc).__name__}: {exc}"
    return SampleResult(
        dataset=entry.dataset,
        path=entry.path,
        tactic=entry.tactic,
        labels=entry.labels,
        events=events,
        alerts=alerts,
        rules_fired=dict(rules),
        techniques_fired=dict(techniques),
        seconds=time.perf_counter() - started,
        error=error,
    )


def replay_dataset(
    source: DatasetSource,
    engine: DetectionEngine,
    *,
    entries: Iterable[DatasetEntry] | None = None,
    alert_sink: Callable[[Alert], None] | None = None,
    progress: Callable[[SampleResult], None] | None = None,
) -> ReplayResult:
    started = time.perf_counter()
    results: list[SampleResult] = []
    for entry in entries if entries is not None else source.entries():
        result = _replay_one(source, entry, engine, alert_sink)
        results.append(result)
        if progress:
            progress(result)
    return ReplayResult(
        rules_loaded=engine.stats.rules_loaded,
        rules_failed=engine.stats.rules_failed,
        samples=results,
        seconds=time.perf_counter() - started,
    )
