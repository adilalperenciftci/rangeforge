"""Sigma correlation rules evaluated in-stream.

Supports the four Sigma correlation types that make sense for a streaming
engine: ``event_count``, ``value_count``, ``temporal`` and
``temporal_ordered``. State is a sliding window per correlation and group-by
key, fed by the alerts of the referenced base rules. A correlation fires once
per group per window; the window is reset after firing so a long-running burst
raises one alert per timespan instead of one per event.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sigma.correlations import (
    SigmaCorrelationCondition,
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
    SigmaCorrelationType,
)

from rangeforge.detect.alerts import Alert
from rangeforge.detect.sigma_compiler import RuleCompileError, attack_tags
from rangeforge.schema.events import NormalizedEvent

SUPPORTED = {
    SigmaCorrelationType.EVENT_COUNT,
    SigmaCorrelationType.VALUE_COUNT,
    SigmaCorrelationType.TEMPORAL,
    SigmaCorrelationType.TEMPORAL_ORDERED,
}

_OPS = {
    SigmaCorrelationConditionOperator.LT: lambda a, b: a < b,
    SigmaCorrelationConditionOperator.LTE: lambda a, b: a <= b,
    SigmaCorrelationConditionOperator.GT: lambda a, b: a > b,
    SigmaCorrelationConditionOperator.GTE: lambda a, b: a >= b,
    SigmaCorrelationConditionOperator.EQ: lambda a, b: a == b,
    SigmaCorrelationConditionOperator.NEQ: lambda a, b: a != b,
}


@dataclass(frozen=True)
class Member:
    time: datetime
    rule_ref: str
    value: str | None
    alert: Alert


@dataclass
class _Window:
    members: deque[Member] = field(default_factory=deque)
    fired_at: datetime | None = None


@dataclass
class CompiledCorrelation:
    rule_id: str
    title: str
    level: str
    kind: SigmaCorrelationType
    rule_refs: tuple[str, ...]
    """Names or ids of the base rules, as written in the correlation."""
    group_by: tuple[str, ...]
    timespan: timedelta
    op: SigmaCorrelationConditionOperator | None
    count: int | None
    fieldref: str | None
    techniques: tuple[str, ...]
    tactics: tuple[str, ...]
    source: str | None = None
    _state: dict[tuple[str, ...], _Window] = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------------ feeding

    def accepts(self, rule_key: set[str]) -> bool:
        return any(ref in rule_key for ref in self.rule_refs)

    def _group_key(self, event: NormalizedEvent) -> tuple[str, ...]:
        return tuple(str(event.field(f, "")) for f in self.group_by)

    def _ref_for(self, rule_key: set[str]) -> str:
        for ref in self.rule_refs:
            if ref in rule_key:
                return ref
        return self.rule_refs[0]

    def feed(self, event: NormalizedEvent, alert: Alert, rule_key: set[str]) -> Alert | None:
        """Add a base-rule alert; return a correlation alert if the condition is met."""
        key = self._group_key(event)
        window = self._state.setdefault(key, _Window())
        now = event.time
        cutoff = now - self.timespan
        while window.members and window.members[0].time < cutoff:
            window.members.popleft()
        if window.fired_at is not None and window.fired_at >= cutoff:
            return None  # already fired for this window
        value = str(event.field(self.fieldref, "")) if self.fieldref else None
        window.members.append(Member(now, self._ref_for(rule_key), value, alert))
        if not self._satisfied(window.members):
            return None
        window.fired_at = now
        members = list(window.members)
        window.members.clear()
        return self._alert(event, members, key)

    # ------------------------------------------------------------------ logic

    def _satisfied(self, members: Iterable[Member]) -> bool:
        members = list(members)
        if self.kind is SigmaCorrelationType.EVENT_COUNT:
            return self._compare(len(members))
        if self.kind is SigmaCorrelationType.VALUE_COUNT:
            return self._compare(len({m.value for m in members if m.value}))
        seen = [m.rule_ref for m in members]
        if self.kind is SigmaCorrelationType.TEMPORAL:
            return all(ref in seen for ref in self.rule_refs)
        # temporal_ordered: every ref appears, in order (subsequence)
        pos = 0
        for ref in seen:
            if pos < len(self.rule_refs) and ref == self.rule_refs[pos]:
                pos += 1
        return pos == len(self.rule_refs)

    def _compare(self, observed: int) -> bool:
        if self.op is None or self.count is None:
            return observed >= 1
        return bool(_OPS[self.op](observed, self.count))

    def _alert(self, event: NormalizedEvent, members: list[Member], key: tuple[str, ...]) -> Alert:
        titles = sorted({m.alert.rule_title for m in members})
        group = ", ".join(f"{f}={v}" for f, v in zip(self.group_by, key, strict=True)) or "global"
        techniques = tuple(
            dict.fromkeys(self.techniques + tuple(t for m in members for t in m.alert.techniques))
        )
        tactics = tuple(
            dict.fromkeys(self.tactics + tuple(t for m in members for t in m.alert.tactics))
        )
        return Alert(
            rule_id=self.rule_id,
            rule_title=self.title,
            level=self.level,
            techniques=techniques,
            tactics=tactics,
            time=event.time,
            hostname=event.device.hostname,
            event_uid=event.metadata.uid,
            source_file=event.metadata.source_file,
            labels=event.metadata.labels,
            summary=f"{self.kind.name.lower()} x{len(members)} [{group}]: "
            + "; ".join(titles)[:240],
            fields={
                "correlation": self.kind.name.lower(),
                "members": len(members),
                "group": group,
                "window_start": members[0].time.isoformat(),
                "window_end": members[-1].time.isoformat(),
                "rules": titles,
            },
        )

    def reset(self) -> None:
        self._state.clear()


def compile_correlation(
    rule: SigmaCorrelationRule, *, source: str | None = None
) -> CompiledCorrelation:
    if rule.type not in SUPPORTED:
        raise RuleCompileError(f"unsupported correlation type {rule.type.name}")
    refs = tuple(str(r.reference) for r in (rule.rules or ()))
    if not refs:
        raise RuleCompileError("correlation references no rules")
    cond = rule.condition
    if cond is not None and not isinstance(cond, SigmaCorrelationCondition):
        raise RuleCompileError("extended (boolean) correlation conditions are not supported")
    fieldref = cond.fieldref if cond else None
    if isinstance(fieldref, list):
        fieldref = fieldref[0] if fieldref else None
    techniques, tactics = attack_tags(rule.tags or ())
    return CompiledCorrelation(
        rule_id=str(rule.id) if rule.id else rule.title,
        title=rule.title,
        level=str(rule.level.name).lower() if rule.level else "medium",
        kind=rule.type,
        rule_refs=refs,
        group_by=tuple(rule.group_by or ()),
        timespan=timedelta(seconds=rule.timespan.seconds),
        op=cond.op if cond else None,
        count=int(cond.count) if cond and cond.count is not None else None,
        fieldref=str(fieldref) if fieldref else None,
        techniques=techniques,
        tactics=tactics,
        source=source,
    )
