from datetime import UTC, datetime, timedelta
from pathlib import Path

from rangeforge.detect import DetectionEngine
from rangeforge.schema.events import EventClass, Metadata, NormalizedEvent

RULES = Path(__file__).resolve().parents[1] / "rules" / "correlation"


def sec(event_id: int, t: datetime, **fields: object) -> NormalizedEvent:
    native: dict[str, object] = {
        "Channel": "Security",
        "EventID": event_id,
        "Computer": "WS01",
        **fields,
    }
    return NormalizedEvent(
        time=t,
        class_uid=EventClass.AUTHENTICATION,
        metadata=Metadata(product="Microsoft-Windows-Security-Auditing", uid=str(t.timestamp())),
        native=native,
    )


def _engine() -> DetectionEngine:
    engine = DetectionEngine()
    engine.load_paths([RULES])
    assert engine.stats.rules_failed == 0, engine.stats.failures
    return engine


def test_rules_load() -> None:
    engine = _engine()
    assert engine.stats.correlations_loaded == 3
    assert engine.stats.rules_loaded == 3


def test_temporal_ordered_fires_once_per_window() -> None:
    engine = _engine()
    t0 = datetime(2024, 1, 1, 12, 0, tzinfo=UTC)
    events = [sec(4625, t0 + timedelta(seconds=i), TargetUserName="alice") for i in range(3)]
    events.append(sec(4624, t0 + timedelta(seconds=5), TargetUserName="alice", LogonType=3))
    events.append(sec(4624, t0 + timedelta(seconds=6), TargetUserName="alice", LogonType=3))
    titles = [a.rule_title for a in engine.run(events)]
    assert titles.count("Brute Force Followed By Successful Logon") == 1


def test_temporal_ordered_requires_order_and_group() -> None:
    engine = _engine()
    t0 = datetime(2024, 1, 1, 12, 0, tzinfo=UTC)
    # success first, then failures: wrong order
    events = [sec(4624, t0, TargetUserName="bob", LogonType=3)]
    events += [sec(4625, t0 + timedelta(seconds=i + 1), TargetUserName="bob") for i in range(3)]
    # failures for carol, success for dave: different group
    events += [sec(4625, t0 + timedelta(seconds=10 + i), TargetUserName="carol") for i in range(3)]
    events.append(sec(4624, t0 + timedelta(seconds=14), TargetUserName="dave", LogonType=3))
    titles = [a.rule_title for a in engine.run(events)]
    assert "Brute Force Followed By Successful Logon" not in titles


def test_value_count_distinct_accounts_and_window_expiry() -> None:
    engine = _engine()
    t0 = datetime(2024, 1, 1, 12, 0, tzinfo=UTC)
    # 9 distinct accounts: below threshold
    events = [sec(4625, t0 + timedelta(seconds=i), TargetUserName=f"u{i}") for i in range(9)]
    # same account repeated: distinct count stays 9
    events += [sec(4625, t0 + timedelta(seconds=20 + i), TargetUserName="u0") for i in range(5)]
    assert "Password Spraying Burst Against One Host" not in [
        a.rule_title for a in engine.run(events)
    ]
    # tenth distinct account inside the window fires it
    fired = [a for a in engine.run([sec(4625, t0 + timedelta(seconds=30), TargetUserName="u9")])]
    corr = [a for a in fired if a.rule_title == "Password Spraying Burst Against One Host"]
    assert len(corr) == 1
    assert corr[0].level == "high"
    assert "T1110.003" in corr[0].techniques
    assert corr[0].fields["members"] == 15
    # far outside the window nothing is remembered
    later = [
        sec(4625, t0 + timedelta(minutes=30, seconds=i), TargetUserName=f"v{i}") for i in range(9)
    ]
    assert "Password Spraying Burst Against One Host" not in [
        a.rule_title for a in engine.run(later)
    ]


def _bf(events: list[NormalizedEvent]) -> int:
    titles = [a.rule_title for a in _engine().run(events)]
    return titles.count("Brute Force Followed By Successful Logon")


def t(h: int, m: int, s: int = 0) -> datetime:
    return datetime(2024, 1, 1, h, m, s, tzinfo=UTC)


def test_out_of_order_arrival_is_ordered_by_event_time() -> None:
    # Arrives: failed@12:02, then success@12:01. In event time the success
    # precedes the failure, so the ordered sequence must NOT fire.
    events = [
        sec(4625, t(12, 2), TargetUserName="eve"),
        sec(4624, t(12, 1), TargetUserName="eve", LogonType=3),
    ]
    assert _bf(events) == 0


def test_late_failures_before_an_early_success_still_fire() -> None:
    # Arrives: success@12:02 first (watermark 12:02), then five failures at
    # 12:01:00..12:01:04 that the collector delivered late. In event time the
    # pattern failed -> success is real and spans 1:00, inside the 10 min window.
    events = [sec(4624, t(12, 2), TargetUserName="fay", LogonType=3)]
    events += [sec(4625, t(12, 1, i), TargetUserName="fay") for i in range(5)]
    assert _bf(events) == 1


def test_window_bound_is_event_time_not_arrival_tolerance() -> None:
    # Rule timespan is 10 min. failed@11:59:45 is inside the keep-buffer
    # (10 min + 30 s lateness behind the 12:10 watermark) but the pattern
    # would span 10:15 > 10 min, so it must not fire.
    events = [sec(4624, t(12, 10), TargetUserName="gus", LogonType=3)]
    events += [sec(4625, t(11, 59, 45), TargetUserName="gus")] * 5
    assert _bf(events) == 0
    # the same failures with a success 9:45 later are a genuine window
    events = [sec(4624, t(12, 9, 30), TargetUserName="hal", LogonType=3)]
    events += [sec(4625, t(11, 59, 45), TargetUserName="hal")] * 5
    assert _bf(events) == 1


def test_events_behind_the_buffer_are_dropped_and_counted() -> None:
    engine = _engine()
    corr = next(c for c in engine.correlations if c.title.startswith("Brute Force"))
    events = [sec(4624, t(12, 10), TargetUserName="ivy", LogonType=3)]
    events += [sec(4625, t(11, 59, 29), TargetUserName="ivy")]  # 10:31 behind
    assert "Brute Force Followed By Successful Logon" not in [
        a.rule_title for a in engine.run(events)
    ]
    assert corr.late_dropped == 1
