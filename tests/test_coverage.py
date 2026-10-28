from collections.abc import Iterator
from datetime import UTC, datetime

from sigma.rule import SigmaRule

from rangeforge.coverage import build_layer, replay_dataset, summarize, to_markdown
from rangeforge.datasets.catalog import DatasetEntry, DatasetSource
from rangeforge.detect import DetectionEngine
from rangeforge.schema.events import EventClass, Metadata, NormalizedEvent

SYSMON = "Microsoft-Windows-Sysmon/Operational"

RULE = """
title: Suspicious tool
tags: [attack.credential_access, attack.t1003.001]
logsource: {product: windows, category: process_creation}
detection:
  sel:
    Image|endswith: '\\\\tool.exe'
  condition: sel
"""


def _event(image: str, labels: tuple[str, ...], source: str) -> NormalizedEvent:
    return NormalizedEvent(
        time=datetime(2024, 1, 1, tzinfo=UTC),
        class_uid=EventClass.PROCESS_ACTIVITY,
        metadata=Metadata(product="t", uid="1", source_file=source, labels=labels),
        native={"Channel": SYSMON, "EventID": 1, "Image": image},
    )


class FakeSource(DatasetSource):
    name = "fake"

    def __init__(self) -> None:
        super().__init__()
        self._entries = [
            DatasetEntry(
                dataset="fake",
                path="a.evtx",
                url="x",
                tactic="credential-access",
                techniques=("T1003.001",),
            ),
            DatasetEntry(
                dataset="fake",
                path="b.evtx",
                url="x",
                tactic="credential-access",
                techniques=("T1003.002",),
            ),
            DatasetEntry(dataset="fake", path="c.evtx", url="x", tactic="execution", techniques=()),
            DatasetEntry(
                dataset="fake", path="d.evtx", url="x", tactic="execution", techniques=("T1059",)
            ),
        ]

    def entries(self) -> list[DatasetEntry]:
        return self._entries

    def replay(self, entry: DatasetEntry) -> Iterator[NormalizedEvent]:
        images = {
            "a.evtx": ["C:\\tool.exe", "C:\\ok.exe"],  # detected with right technique
            "b.evtx": ["C:\\tool.exe"],  # alert, but wrong technique (noisy)
            "c.evtx": ["C:\\ok.exe"],  # unlabelled, nothing fires
            "d.evtx": ["C:\\ok.exe"],  # labelled, nothing fires -> missed
        }
        for image in images[entry.path]:
            yield _event(image, entry.labels, entry.path)


def test_replay_and_summary() -> None:
    engine = DetectionEngine()
    engine.add_sigma(SigmaRule.from_yaml(RULE))
    result = replay_dataset(FakeSource(), engine)
    assert result.events == 5
    summary = summarize(result)

    assert summary.samples == 4
    assert summary.labelled == 3
    assert summary.detected_any == 2
    assert summary.detected_labelled == 1
    assert [s.path for s in summary.missed] == ["d.evtx"]
    assert summary.techniques["T1003.001"].detected == 1
    assert summary.techniques["T1003.002"].noisy == 1
    assert summary.tactics["credential-access"].detected_any == 2
    assert summary.top_rules == [("Suspicious tool", 2)]

    md = to_markdown(summary)
    assert "| T1003.001 | 1 | 1 | 100% | 0 |" in md
    assert "`d.evtx`" in md

    layer = build_layer(summary)
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert scores == {"T1003.001": 100, "T1003.002": 0, "T1059": 0}
    assert layer["domain"] == "enterprise-attack"


def test_parent_technique_counts_as_hit() -> None:
    engine = DetectionEngine()
    engine.add_sigma(SigmaRule.from_yaml(RULE.replace("t1003.001", "t1003")))
    result = replay_dataset(FakeSource(), engine, entries=FakeSource().entries()[:1])
    assert result.samples[0].detected_labelled


def test_technique_hit_semantics() -> None:
    from rangeforge.coverage.replay import technique_hit

    assert technique_hit("T1003.001", {"T1003.001"})
    assert technique_hit("T1003.001", {"T1003"})
    assert technique_hit("T1003", {"T1003.004"})
    assert not technique_hit("T1003.002", {"T1003.001"})
    assert not technique_hit("T1059", {"T1003"})
