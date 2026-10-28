"""Compile Sigma rules into native Python predicates.

pySigma parses a rule into a condition AST. Instead of converting to a query
language for an external SIEM, we walk the AST once and produce a closure that
evaluates directly against ``NormalizedEvent.native``. Thousands of rules then
run in-process over a stream of events with no database in the loop.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

from rangeforge.detect.logsource import EventFilter, resolve_logsource
from rangeforge.schema.events import NormalizedEvent

Predicate = Callable[[NormalizedEvent, dict[str, str] | None], bool]

_ATTACK_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_ATTACK_TACTIC = re.compile(r"^attack\.([a-z_-]+)$", re.IGNORECASE)


class RuleCompileError(Exception):
    pass


@dataclass(frozen=True)
class CompiledRule:
    rule_id: str
    title: str
    name: str | None
    level: str
    status: str
    techniques: tuple[str, ...]
    tactics: tuple[str, ...]
    event_filter: EventFilter
    predicate: Predicate
    fields: tuple[str, ...]
    """Fields the rule author flagged as useful context."""
    source: str | None = None

    @property
    def keys(self) -> set[str]:
        """Identifiers a correlation rule may reference this rule by."""
        return {k for k in (self.rule_id, self.name) if k}

    def matches(self, event: NormalizedEvent) -> bool:
        channel = event.native.get("Channel")
        event_id = event.native.get("EventID")
        if not self.event_filter.accepts(channel, event_id):
            return False
        aliases = self.event_filter.alias_map(channel, event_id)
        return self.predicate(event, aliases)


# --------------------------------------------------------------------------- values


def _lookup(event: NormalizedEvent, field_name: str, aliases: dict[str, str] | None) -> Any:
    native = event.native
    if aliases and field_name in aliases:
        alt = aliases[field_name]
        if alt in native:
            return native[alt]
    if field_name in native:
        return native[field_name]
    # Sigma allows dotted/nested names; we only store flat keys. Fall back to
    # case-insensitive lookup (Windows field names are not reliably cased).
    return event.field(field_name)


def _as_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list | tuple):
        out: list[str] = []
        for item in value:
            out.extend(_as_strings(item))
        return out
    if isinstance(value, bool):
        return ["true" if value else "false"]
    return [str(value)]


def _as_numbers(value: Any) -> list[float]:
    out: list[float] = []
    for text in _as_strings(value):
        try:
            if text.lower().startswith("0x"):
                out.append(float(int(text, 16)))
            else:
                out.append(float(text))
        except ValueError:
            continue
    return out


ValueMatcher = Callable[[Any], bool]


def sigma_string_to_regex(value: SigmaString) -> str:
    """Render a SigmaString (plain parts + wildcards) as an anchored-free regex."""
    out: list[str] = []
    for part in value.s:
        if part is SpecialChars.WILDCARD_MULTI:
            out.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            out.append(".")
        else:
            out.append(re.escape(str(part)))
    return "".join(out)


def _regex_flags(value: SigmaRegularExpression) -> int:
    flags = 0
    for flag in value.flags:
        flags |= value.sigma_to_python_flags[flag]
    return flags


# Per-event cache of lower-cased field values. Long values (script blocks,
# command lines) are matched by hundreds of rules per event; folding them once
# is the single biggest win in the engine. The engine clears it per event; the
# engine itself is single-threaded.
_LOWER: dict[str, str] = {}


def reset_eval_cache() -> None:
    _LOWER.clear()


def _lower(s: str) -> str:
    # Keyed by the string itself: CPython caches str hashes, so repeated
    # lookups of the same long value cost one hash in total.
    cached = _LOWER.get(s)
    if cached is None:
        cached = s.lower()
        _LOWER[s] = cached
    return cached


def _identity(s: str) -> str:
    return s


def _affix_form(value: SigmaString) -> tuple[str, str] | None:
    """Recognise ``*x*`` / ``*x`` / ``x*`` / ``x`` shapes that need no regex.

    Returns (mode, text) with mode in contains|endswith|startswith|exact, or
    None when the pattern has inner wildcards.
    """
    parts = list(value.s)
    lead = trail = False
    while parts and parts[0] is SpecialChars.WILDCARD_MULTI:
        parts.pop(0)
        lead = True
    while parts and parts[-1] is SpecialChars.WILDCARD_MULTI:
        parts.pop()
        trail = True
    if any(not isinstance(part, str) for part in parts):
        return None
    text = "".join(str(part) for part in parts)
    if lead and trail:
        return "contains", text
    if lead:
        return "endswith", text
    if trail:
        return "startswith", text
    return "exact", text


def _string_matcher(value: SigmaString) -> ValueMatcher:
    fold = not isinstance(value, SigmaCasedString)
    affix = _affix_form(value)
    if affix is not None:
        mode, text = affix
        needle = text.lower() if fold else text
        norm = _lower if fold else _identity
        if mode == "exact":
            return lambda v: any(norm(s) == needle for s in _as_strings(v))
        if mode == "contains":
            return lambda v: any(needle in norm(s) for s in _as_strings(v))
        if mode == "endswith":
            return lambda v: any(norm(s).endswith(needle) for s in _as_strings(v))
        return lambda v: any(norm(s).startswith(needle) for s in _as_strings(v))

    flags = re.DOTALL | (re.IGNORECASE if fold else 0)
    pattern = re.compile(sigma_string_to_regex(value), flags)

    def wildcard(v: Any) -> bool:
        return any(pattern.fullmatch(s) is not None for s in _as_strings(v))

    return wildcard


def _value_matcher(value: Any) -> ValueMatcher:
    if isinstance(value, SigmaString):
        return _string_matcher(value)
    if isinstance(value, SigmaNumber):
        target = float(value.number)
        return lambda v: target in _as_numbers(v)
    if isinstance(value, SigmaBool):
        target_bool = bool(value.boolean)
        return lambda v: any(s.lower() == str(target_bool).lower() for s in _as_strings(v))
    if isinstance(value, SigmaNull):
        return lambda v: v is None or v == ""
    if isinstance(value, SigmaRegularExpression):
        compiled = re.compile(str(value.regexp), _regex_flags(value))
        return lambda v: any(compiled.search(s) is not None for s in _as_strings(v))
    if isinstance(value, SigmaCIDRExpression):
        network = ipaddress.ip_network(value.cidr, strict=False)

        def in_cidr(v: Any) -> bool:
            for s in _as_strings(v):
                try:
                    if ipaddress.ip_address(s) in network:
                        return True
                except ValueError:
                    continue
            return False

        return in_cidr
    if isinstance(value, SigmaCompareExpression):
        op = value.op
        number = float(value.number.number)
        ops = SigmaCompareExpression.CompareOperators
        table: dict[Any, Callable[[float], bool]] = {
            ops.LT: lambda n: n < number,
            ops.LTE: lambda n: n <= number,
            ops.GT: lambda n: n > number,
            ops.GTE: lambda n: n >= number,
            ops.NEQ: lambda n: n != number,
        }
        check = table[op]
        return lambda v: any(check(n) for n in _as_numbers(v))
    if isinstance(value, SigmaExpansion):
        matchers = [_value_matcher(v) for v in value.values]
        return lambda v: any(m(v) for m in matchers)
    raise RuleCompileError(f"unsupported value type {type(value).__name__}")


# --------------------------------------------------------------------------- conditions


def _compile_field_expr(node: ConditionFieldEqualsValueExpression) -> Predicate:
    field_name = node.field
    value = node.value

    if isinstance(value, SigmaExists):
        want = bool(value.exists)

        def exists(event: NormalizedEvent, aliases: dict[str, str] | None) -> bool:
            return (_lookup(event, field_name, aliases) is not None) == want

        return exists

    if isinstance(value, SigmaFieldReference):
        other = value.field

        def field_ref(event: NormalizedEvent, aliases: dict[str, str] | None) -> bool:
            left = _as_strings(_lookup(event, field_name, aliases))
            right = _as_strings(_lookup(event, other, aliases))
            return bool(left) and any(a.lower() == b.lower() for a in left for b in right)

        return field_ref

    if isinstance(value, SigmaNull):

        def is_null(event: NormalizedEvent, aliases: dict[str, str] | None) -> bool:
            v = _lookup(event, field_name, aliases)
            return v is None or v == ""

        return is_null

    matcher = _value_matcher(value)

    def field_eq(event: NormalizedEvent, aliases: dict[str, str] | None) -> bool:
        v = _lookup(event, field_name, aliases)
        return v is not None and matcher(v)

    return field_eq


def _compile_keyword(node: ConditionValueExpression) -> Predicate:
    value = node.value
    if isinstance(value, SigmaString):
        flags = re.DOTALL | (0 if isinstance(value, SigmaCasedString) else re.IGNORECASE)
        # Keyword search is a substring match unless the author used wildcards.
        regex = sigma_string_to_regex(value) if value.contains_special() else re.escape(str(value))
        pattern = re.compile(regex, flags)

        def keyword(event: NormalizedEvent, aliases: dict[str, str] | None) -> bool:
            for v in event.native.values():
                for s in _as_strings(v):
                    if pattern.search(s):
                        return True
            return False

        return keyword

    matcher = _value_matcher(value)

    def keyword_any(event: NormalizedEvent, aliases: dict[str, str] | None) -> bool:
        return any(matcher(v) for v in event.native.values())

    return keyword_any


def _compile_condition(node: ConditionItem | Any) -> Predicate:
    if isinstance(node, ConditionAND):
        parts = [_compile_condition(a) for a in node.args]
        return lambda e, a: all(p(e, a) for p in parts)
    if isinstance(node, ConditionOR):
        parts = [_compile_condition(a) for a in node.args]
        return lambda e, a: any(p(e, a) for p in parts)
    if isinstance(node, ConditionNOT):
        inner = _compile_condition(node.args[0])
        return lambda e, a: not inner(e, a)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _compile_field_expr(node)
    if isinstance(node, ConditionValueExpression):
        return _compile_keyword(node)
    raise RuleCompileError(f"unsupported condition node {type(node).__name__}")


# --------------------------------------------------------------------------- rules


def attack_tags(tags: Iterable[Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split Sigma tags into (technique ids, tactic slugs)."""
    techniques: list[str] = []
    tactics: list[str] = []
    for tag in tags:
        text = str(tag)
        m = _ATTACK_TECHNIQUE.match(text)
        if m:
            techniques.append(m.group(1).upper())
            continue
        m = _ATTACK_TACTIC.match(text)
        if m and not m.group(1).lower().startswith(("s0", "g0", "m1")):
            tactics.append(m.group(1).lower().replace("_", "-"))
    return tuple(techniques), tuple(tactics)


def _event_ids_in(node: Any) -> frozenset[int] | None:
    """Static EventID constraint implied by a condition, or None if unbounded.

    ``EventID: 4624`` (or a list) under AND/OR is recognised; anything negated
    or non-numeric leaves the rule unbounded.
    """
    if isinstance(node, ConditionFieldEqualsValueExpression):
        if node.field != "EventID":
            return None
        value = node.value
        if isinstance(value, SigmaNumber):
            return frozenset({int(value.number)})
        if isinstance(value, SigmaString) and not value.contains_special():
            text = str(value)
            return frozenset({int(text)}) if text.isdigit() else None
        return None
    if isinstance(node, ConditionOR):
        out: set[int] = set()
        for arg in node.args:
            ids = _event_ids_in(arg)
            if ids is None:
                return None
            out |= ids
        return frozenset(out)
    if isinstance(node, ConditionAND):
        found: frozenset[int] | None = None
        for arg in node.args:
            ids = _event_ids_in(arg)
            if ids is not None:
                found = ids if found is None else (found & ids)
        return found
    return None


def _narrow_filter(event_filter: EventFilter, conditions: list[Any]) -> EventFilter:
    if event_filter.unrestricted or event_filter.event_ids() is not None:
        return event_filter
    union: set[int] = set()
    for cond in conditions:
        ids = _event_ids_in(cond.parsed)
        if ids is None:
            return event_filter
        union |= ids
    if not union:
        return event_filter
    channels: dict[str, frozenset[int] | None] = dict.fromkeys(
        event_filter.channels, frozenset(union)
    )
    return EventFilter(channels=channels, aliases=event_filter.aliases)


def compile_rule(rule: SigmaRule, *, source: str | None = None) -> CompiledRule:
    """Compile one parsed Sigma rule. Raises RuleCompileError for unsupported features."""
    conditions = rule.detection.parsed_condition
    if not conditions:
        raise RuleCompileError("rule has no condition")
    predicates: list[Predicate] = []
    for cond in conditions:
        try:
            predicates.append(_compile_condition(cond.parsed))
        except Exception as exc:  # pySigma raises many error types while parsing
            raise RuleCompileError(str(exc)) from exc
    predicate: Predicate = (
        predicates[0] if len(predicates) == 1 else (lambda e, a: any(p(e, a) for p in predicates))
    )
    techniques, tactics = attack_tags(rule.tags or ())
    ls = rule.logsource
    return CompiledRule(
        rule_id=str(rule.id) if rule.id else rule.title,
        title=rule.title,
        name=rule.name,
        level=str(rule.level.name).lower() if rule.level else "medium",
        status=str(rule.status.name).lower() if rule.status else "unknown",
        techniques=techniques,
        tactics=tactics,
        event_filter=_narrow_filter(
            resolve_logsource(ls.product, ls.category, ls.service), list(conditions)
        ),
        predicate=predicate,
        fields=tuple(rule.fields or ()),
        source=source,
    )
