"""Streaming detection engine: loads Sigma rules, indexes them by event id and
evaluates every incoming event against the applicable subset."""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

from rangeforge.detect.alerts import Alert
from rangeforge.detect.correlation import CompiledCorrelation, compile_correlation
from rangeforge.detect.sigma_compiler import CompiledRule, RuleCompileError, compile_rule
from rangeforge.schema.events import NormalizedEvent

log = logging.getLogger(__name__)

DEFAULT_CONTEXT_FIELDS = (
    "Image",
    "CommandLine",
    "ParentImage",
    "ParentCommandLine",
    "User",
    "TargetImage",
    "SourceImage",
    "TargetFilename",
    "TargetObject",
    "Details",
    "ImageLoaded",
    "DestinationIp",
    "DestinationPort",
    "QueryName",
    "TargetUserName",
    "SubjectUserName",
    "LogonType",
    "IpAddress",
    "ServiceName",
    "ScriptBlockText",
)


@dataclass
class EngineStats:
    rules_loaded: int = 0
    rules_failed: int = 0
    correlations_loaded: int = 0
    events_seen: int = 0
    alerts: int = 0
    seconds: float = 0.0
    failures: dict[str, str] = field(default_factory=dict)

    @property
    def events_per_second(self) -> float:
        return self.events_seen / self.seconds if self.seconds else 0.0


class DetectionEngine:
    def __init__(self, *, context_fields: tuple[str, ...] = DEFAULT_CONTEXT_FIELDS) -> None:
        self.rules: list[CompiledRule] = []
        self._by_event_id: dict[int, list[CompiledRule]] = defaultdict(list)
        self._any_event_id: list[CompiledRule] = []
        self.correlations: list[CompiledCorrelation] = []
        self._corr_by_ref: dict[str, list[CompiledCorrelation]] = defaultdict(list)
        self.stats = EngineStats()
        self.context_fields = context_fields

    # ------------------------------------------------------------------ loading

    def add_rule(self, rule: CompiledRule) -> None:
        self.rules.append(rule)
        ids = rule.event_filter.event_ids()
        if ids is None:
            self._any_event_id.append(rule)
        else:
            for event_id in ids:
                self._by_event_id[event_id].append(rule)
        self.stats.rules_loaded += 1

    def add_correlation(self, rule: SigmaCorrelationRule, *, source: str | None = None) -> bool:
        try:
            compiled = compile_correlation(rule, source=source)
        except RuleCompileError as exc:
            self.stats.rules_failed += 1
            self.stats.failures[source or rule.title] = str(exc)
            return False
        self.correlations.append(compiled)
        for ref in compiled.rule_refs:
            self._corr_by_ref[ref].append(compiled)
        self.stats.correlations_loaded += 1
        return True

    def add_sigma(self, rule: SigmaRule, *, source: str | None = None) -> bool:
        try:
            self.add_rule(compile_rule(rule, source=source))
        except RuleCompileError as exc:
            self.stats.rules_failed += 1
            self.stats.failures[source or rule.title] = str(exc)
            return False
        return True

    def load_paths(
        self,
        paths: Iterable[Path],
        *,
        include_status: frozenset[str] | None = None,
    ) -> int:
        """Load every ``*.yml`` under the given files/directories.

        ``include_status`` optionally restricts to Sigma statuses
        (``experimental``, ``test``, ``stable``, ...); deprecated/unsupported
        rules are always skipped.
        """
        before = self.stats.rules_loaded
        files: list[Path] = []
        for p in paths:
            files.extend(sorted(p.rglob("*.yml")) if p.is_dir() else [p])
        for file in files:
            try:
                collection = SigmaCollection.load_ruleset([str(file)], collect_errors=True)
            except SigmaError as exc:
                self.stats.rules_failed += 1
                self.stats.failures[str(file)] = str(exc)
                continue
            for item in collection.rules:
                if isinstance(item, SigmaCorrelationRule):
                    self.add_correlation(item, source=str(file))
                    continue
                if not isinstance(item, SigmaRule):
                    continue
                if item.errors:
                    self.stats.rules_failed += 1
                    self.stats.failures[str(file)] = "; ".join(str(e) for e in item.errors)
                    continue
                status = str(item.status.name).lower() if item.status else "unknown"
                if status in {"deprecated", "unsupported"}:
                    continue
                if include_status and status not in include_status:
                    continue
                self.add_sigma(item, source=str(file))
        return self.stats.rules_loaded - before

    # ------------------------------------------------------------------ matching

    def candidates(self, event: NormalizedEvent) -> Iterator[CompiledRule]:
        event_id = event.native.get("EventID")
        if isinstance(event_id, int):
            yield from self._by_event_id.get(event_id, ())
        yield from self._any_event_id

    def evaluate(self, event: NormalizedEvent) -> list[Alert]:
        self.stats.events_seen += 1
        alerts: list[Alert] = []
        for rule in self.candidates(event):
            try:
                hit = rule.matches(event)
            except Exception:  # a broken rule must never stop the stream
                log.exception("rule %s raised during evaluation", rule.rule_id)
                continue
            if not hit:
                continue
            alert = Alert.from_event(
                event,
                rule_id=rule.rule_id,
                rule_title=rule.title,
                level=rule.level,
                techniques=rule.techniques,
                tactics=rule.tactics,
                keep_fields=rule.fields or self.context_fields,
            )
            alerts.append(alert)
            if self.correlations:
                alerts.extend(self._correlate(event, alert, rule))
        self.stats.alerts += len(alerts)
        return alerts

    def _correlate(self, event: NormalizedEvent, alert: Alert, rule: CompiledRule) -> list[Alert]:
        keys = rule.keys
        out: list[Alert] = []
        seen: set[int] = set()
        for key in keys:
            for corr in self._corr_by_ref.get(key, ()):
                if id(corr) in seen:
                    continue
                seen.add(id(corr))
                fired = corr.feed(event, alert, keys)
                if fired is not None:
                    out.append(fired)
        return out

    def run(self, events: Iterable[NormalizedEvent]) -> Iterator[Alert]:
        started = time.perf_counter()
        try:
            for event in events:
                yield from self.evaluate(event)
        finally:
            self.stats.seconds += time.perf_counter() - started
