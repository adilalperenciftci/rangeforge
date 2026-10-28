from datetime import UTC, datetime

import pytest
from sigma.rule import SigmaRule

from rangeforge.detect import DetectionEngine, compile_rule
from rangeforge.schema.events import EventClass, Metadata, NormalizedEvent


def ev(channel: str, event_id: int, **fields: object) -> NormalizedEvent:
    native: dict[str, object] = {"Channel": channel, "EventID": event_id, **fields}
    return NormalizedEvent(
        time=datetime(2024, 1, 1, tzinfo=UTC),
        class_uid=EventClass.PROCESS_ACTIVITY,
        metadata=Metadata(product="test", uid="1"),
        native=native,
    )


SYSMON = "Microsoft-Windows-Sysmon/Operational"

RULE = """
title: Whoami via cmd
id: 11111111-1111-1111-1111-111111111111
status: test
level: medium
tags:
  - attack.discovery
  - attack.t1033
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Image|endswith: '\\\\cmd.exe'
    CommandLine|contains|all:
      - '/c'
      - 'whoami'
  filter:
    ParentImage|contains: 'trusted'
  condition: sel and not filter
"""


def test_compile_metadata() -> None:
    rule = compile_rule(SigmaRule.from_yaml(RULE))
    assert rule.techniques == ("T1033",)
    assert rule.tactics == ("discovery",)
    assert rule.level == "medium"
    assert rule.event_filter.event_ids() == frozenset({1, 4688})


def test_match_sysmon_and_filter() -> None:
    rule = compile_rule(SigmaRule.from_yaml(RULE))
    hit = ev(SYSMON, 1, Image="C:\\Windows\\System32\\CMD.EXE", CommandLine="cmd /c whoami /all")
    assert rule.matches(hit)
    filtered = ev(
        SYSMON, 1, Image="C:\\x\\cmd.exe", CommandLine="cmd /c whoami", ParentImage="C:\\trusted\\a"
    )
    assert not rule.matches(filtered)
    wrong_id = ev(SYSMON, 3, Image="C:\\x\\cmd.exe", CommandLine="cmd /c whoami")
    assert not rule.matches(wrong_id)
    missing = ev(SYSMON, 1, Image="C:\\x\\cmd.exe", CommandLine="cmd /c dir")
    assert not rule.matches(missing)


def test_security_4688_aliases() -> None:
    rule = compile_rule(SigmaRule.from_yaml(RULE))
    hit = ev("Security", 4688, NewProcessName="C:\\Windows\\cmd.exe", CommandLine="cmd /c whoami")
    assert rule.matches(hit)


@pytest.mark.parametrize(
    ("detection", "fields", "expected"),
    [
        ("  sel:\n    DestinationPort: 4444\n  condition: sel", {"DestinationPort": "4444"}, True),
        ("  sel:\n    DestinationPort|gt: 1024\n  condition: sel", {"DestinationPort": 80}, False),
        ("  sel:\n    DestinationPort|gte: 80\n  condition: sel", {"DestinationPort": 80}, True),
        ("  sel:\n    SourceIp|cidr: 10.0.0.0/8\n  condition: sel", {"SourceIp": "10.9.8.7"}, True),
        (
            "  sel:\n    SourceIp|cidr: 10.0.0.0/8\n  condition: sel",
            {"SourceIp": "192.168.1.1"},
            False,
        ),
        ("  sel:\n    CommandLine|re: 'a.c'\n  condition: sel", {"CommandLine": "xxabcxx"}, True),
        (
            "  sel:\n    CommandLine|re: '^a.c$'\n  condition: sel",
            {"CommandLine": "xxabcxx"},
            False,
        ),
        (
            "  sel:\n    Image|startswith: 'C:\\\\Temp'\n  condition: sel",
            {"Image": "c:\\temp\\x"},
            True,
        ),
        ("  sel:\n    Image|cased: 'C:\\\\x'\n  condition: sel", {"Image": "c:\\x"}, False),
        ("  sel:\n    Image|exists: true\n  condition: sel", {"Image": "x"}, True),
        ("  sel:\n    Image|exists: true\n  condition: sel", {}, False),
        ("  sel:\n    Image: null\n  condition: sel", {}, True),
        ("  kw:\n    - 'mimi*katz'\n  condition: kw", {"Other": "abc MIMIkatz"}, True),
        ("  kw:\n    - 'mimi?katz'\n  condition: kw", {"Other": "abc MIMIkatz"}, False),
        ("  kw:\n    - 'mimi*katz'\n  condition: kw", {"Other": "MIMIxxkatz"}, True),
        (
            "  kw:\n    - 'sekurlsa'\n  condition: kw",
            {"CommandLine": "x sekurlsa::logonpasswords"},
            True,
        ),
        (
            "  sel:\n    CommandLine|windash|contains: '-nop'\n  condition: sel",
            {"CommandLine": "powershell /nop"},
            True,
        ),
        (
            "  a:\n    Image|endswith: 'a.exe'\n  b:\n    Image|endswith: 'b.exe'\n  condition: 1 of a*",
            {"Image": "x\\b.exe"},
            False,
        ),
        (
            "  sel_a:\n    Image|endswith: 'a.exe'\n  sel_b:\n    Image|endswith: 'b.exe'\n  condition: 1 of sel_*",
            {"Image": "x\\b.exe"},
            True,
        ),
    ],
)
def test_modifiers(detection: str, fields: dict[str, object], expected: bool) -> None:
    yaml = (
        "title: t\nlogsource:\n  product: windows\n  category: network_connection\n"
        f"detection:\n{detection}\n"
    )
    rule = compile_rule(SigmaRule.from_yaml(yaml))
    assert rule.matches(ev(SYSMON, 3, **fields)) is expected


def test_engine_indexes_and_alerts() -> None:
    engine = DetectionEngine()
    engine.add_sigma(SigmaRule.from_yaml(RULE))
    events = [
        ev(SYSMON, 1, Image="C:\\cmd.exe", CommandLine="cmd /c whoami", User="LAB\\a"),
        ev(SYSMON, 3, DestinationIp="1.2.3.4"),
        ev(SYSMON, 1, Image="C:\\notepad.exe", CommandLine="notepad"),
    ]
    alerts = list(engine.run(events))
    assert len(alerts) == 1
    assert alerts[0].rule_title == "Whoami via cmd"
    assert alerts[0].techniques == ("T1033",)
    assert alerts[0].fields["User"] == "LAB\\a"
    assert engine.stats.events_seen == 3
    assert engine.stats.alerts == 1


def test_wildcard_spans_newlines() -> None:
    yaml = (
        "title: t\nlogsource:\n  product: windows\n  category: ps_script\n"
        "detection:\n  sel:\n    ScriptBlockText|contains: 'needle'\n  condition: sel\n"
    )
    rule = compile_rule(SigmaRule.from_yaml(yaml))
    multi = ev(
        "Microsoft-Windows-PowerShell/Operational", 4104, ScriptBlockText="a\r\nb needle\r\nc"
    )
    assert rule.matches(multi)
