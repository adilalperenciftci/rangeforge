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
