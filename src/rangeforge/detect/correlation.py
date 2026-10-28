"""Sigma correlation rules evaluated in-stream.

Supports the four Sigma correlation types that make sense for a streaming
engine: ``event_count``, ``value_count``, ``temporal`` and
``temporal_ordered``.

Events do not arrive in event-time order. A collector polls several channels,
each with its own lag, and a late Security 4625 may land after the 4624 that
followed it. The engine therefore separates two notions that are easy to
conflate:

* **Arrival tolerance.** Per group a *watermark* tracks the latest event time
  seen. State is kept for ``timespan + lateness`` behind the watermark; an
  event older than that can no longer belong to any window the engine could
  still evaluate and is dropped (counted in ``late_dropped``).
* **Window membership.** The buffer is kept sorted by event time, and the
  condition is evaluated over *event-time* windows ``[start, start + timespan]``
  anchored at each buffered member. The lateness tolerance never widens a
  window: an event that arrives late but falls inside a genuine window counts;
  one that falls outside does not, however early it was accepted.

A correlation fires at most once per group per timespan: after a match the
matched members are consumed and the group stays quiet for one further
timespan, so a long burst raises one alert per window instead of one per
event. Late arrivals that fall into a reported or quiet period are ignored.
"""

from __future__ import annotations

from bisect import insort
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

DEFAULT_LATENESS = timedelta(seconds=30)
"""How far behind the per-group watermark an event may arrive and still be
buffered. Collector polling intervals in this project are well under this."""

_OPS = {
    SigmaCorrelationConditionOperator.LT: lambda a, b: a < b,
    SigmaCorrelationConditionOperator.LTE: lambda a, b: a <= b,
    SigmaCorrelationConditionOperator.GT: lambda a, b: a > b,
    SigmaCorrelationConditionOperator.GTE: lambda a, b: a >= b,
    SigmaCorrelationConditionOperator.EQ: lambda a, b: a == b,
    SigmaCorrelationConditionOperator.NEQ: lambda a, b: a != b,
}


@dataclass(frozen=True, order=True)
class Member:
    time: datetime
    seq: int
    """Arrival order; breaks ties between equal timestamps deterministically."""
    rule_ref: str = field(compare=False)
    value: str | None = field(compare=False)
    alert: Alert = field(compare=False)


@dataclass
class _Window:
    members: list[Member] = field(default_factory=list)
    """Sorted by (time, seq)."""
    watermark: datetime | None = None
    quiet_until: datetime | None = None
    """End of the last matched window plus one timespan; events up to here
    belong to a reported window or its quiet period and are not buffered."""


@dataclass(frozen=True)
class _Match:
    start: datetime
    end: datetime
    members: list[Member]


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
    lateness: timedelta = DEFAULT_LATENESS
    late_dropped: int = 0
    """Events discarded because they arrived more than ``timespan + lateness``
    behind their group's watermark."""
    _state: dict[tuple[str, ...], _Window] = field(default_factory=dict, repr=False)
    _seq: int = field(default=0, repr=False)

    # ------------------------------------------------------------------ feeding

    def accepts(self, rule_key: set[str]) -> bool:
        return any(ref in rule_key for ref in self.rule_refs)

    @property
    def buffer(self) -> timedelta:
        return self.timespan + self.lateness

    def _group_key(self, event: NormalizedEvent) -> tuple[str, ...]:
        return tuple(str(event.field(f, "")) for f in self.group_by)

    def _ref_for(self, rule_key: set[str]) -> str:
        for ref in self.rule_refs:
            if ref in rule_key:
                return ref
        return self.rule_refs[0]

    def feed(self, event: NormalizedEvent, alert: Alert, rule_key: set[str]) -> Alert | None:
        """Add a base-rule alert; return a correlation alert if a window matches."""
        key = self._group_key(event)
        window = self._state.setdefault(key, _Window())
        t = event.time
        if window.watermark is None or t > window.watermark:
            window.watermark = t
        horizon = window.watermark - self.buffer
        if t < horizon:
            self.late_dropped += 1
            return None
        if window.quiet_until is not None and t <= window.quiet_until:
            return None  # already reported, or inside the quiet period after it
        # prune the sorted buffer from the front
        keep = 0
        while keep < len(window.members) and window.members[keep].time < horizon:
            keep += 1
        if keep:
            del window.members[:keep]
        self._seq += 1
        value = str(event.field(self.fieldref, "")) if self.fieldref else None
        insort(window.members, Member(t, self._seq, self._ref_for(rule_key), value, alert))
        match = self._find_window(window.members)
        if match is None:
            return None
        window.quiet_until = match.end + self.timespan
        window.members = [m for m in window.members if m.time > window.quiet_until]
        return self._alert(event, match, key)

    # ------------------------------------------------------------------ logic

    def _find_window(self, members: list[Member]) -> _Match | None:
        """First event-time window ``[start, start + timespan]`` that satisfies
        the condition, scanning candidate starts in time order."""
        for i, start in enumerate(members):
            limit = start.time + self.timespan
            inside = [m for m in members[i:] if m.time <= limit]
            match = self._check(inside)
            if match is not None:
                return _Match(start.time, match[-1].time, match)
        return None

    def _check(self, members: list[Member]) -> list[Member] | None:
        """Members (time-sorted, all within one window) that satisfy the
        condition, or None. Returned members end at the moment the condition
        became true so a later window can start after that point."""
        if self.kind is SigmaCorrelationType.EVENT_COUNT:
            return members if self._compare(len(members)) else None
        if self.kind is SigmaCorrelationType.VALUE_COUNT:
            return members if self._compare(len({m.value for m in members if m.value})) else None
        if self.kind is SigmaCorrelationType.TEMPORAL:
            seen: set[str] = set()
            for idx, m in enumerate(members):
                seen.add(m.rule_ref)
                if all(ref in seen for ref in self.rule_refs):
                    return members[: idx + 1]
            return None
        # temporal_ordered: refs appear as a subsequence, in event-time order
        if members[0].rule_ref != self.rule_refs[0]:
            return None
        pos = 0
        for idx, m in enumerate(members):
            if m.rule_ref == self.rule_refs[pos]:
                pos += 1
                if pos == len(self.rule_refs):
                    return members[: idx + 1]
        return None

    def _compare(self, observed: int) -> bool:
        if self.op is None or self.count is None:
            return observed >= 1
        return bool(_OPS[self.op](observed, self.count))

    def _alert(self, event: NormalizedEvent, match: _Match, key: tuple[str, ...]) -> Alert:
        members = match.members
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
            time=match.end,
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
                "window_start": match.start.isoformat(),
                "window_end": match.end.isoformat(),
                "rules": titles,
            },
        )

    def reset(self) -> None:
        self._state.clear()
        self.late_dropped = 0


def compile_correlation(
    rule: SigmaCorrelationRule,
    *,
    source: str | None = None,
    lateness: timedelta = DEFAULT_LATENESS,
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
        lateness=lateness,
    )
