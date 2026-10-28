from datetime import UTC, datetime
from pathlib import Path

from sigma.rule import SigmaRule

from rangeforge.bench import build_tasks, load_tasks, save_tasks
from rangeforge.bench.backends import create
from rangeforge.bench.prompt import looks_like_refusal, parse_answer
from rangeforge.bench.runner import run_tasks
from rangeforge.bench.score import Leaderboard, score_run
from rangeforge.detect import DetectionEngine
from rangeforge.schema.events import EventClass, Metadata, NormalizedEvent
from tests.test_coverage import RULE, FakeSource

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def _benign(image: str) -> NormalizedEvent:
    return NormalizedEvent(
        time=datetime(2024, 1, 2, tzinfo=UTC),
        class_uid=EventClass.PROCESS_ACTIVITY,
        metadata=Metadata(product="t", uid="9", source_file="live"),
        native={"Channel": SYSMON, "EventID": 1, "Image": image, "User": "LAB\\svc"},
    )


def _engine() -> DetectionEngine:
    engine = DetectionEngine()
    engine.add_sigma(SigmaRule.from_yaml(RULE))
    return engine


def test_build_tasks_populations() -> None:
    benign = [_benign("C:\\ok.exe"), _benign("C:\\tool.exe"), _benign("C:\\ok.exe")]
    tasks = build_tasks(FakeSource(), _engine(), benign_events=iter(benign))
    verdicts = sorted(t.truth.verdict for t in tasks)
    # a.evtx -> malicious (technique matches); b.evtx alert skipped (sibling technique);
    # live tool.exe -> benign
    assert verdicts == ["benign", "malicious"]
    malicious = next(t for t in tasks if t.truth.verdict == "malicious")
    assert malicious.truth.techniques == ("T1003.001",)
    assert malicious.truth.origin == "a.evtx"
    assert any(c.is_trigger for c in malicious.context)
    prompt = malicious.to_prompt_dict()
    assert "truth" not in prompt and "a.evtx" not in str(prompt)
    assert prompt["alert"]["rule"] == "Suspicious tool"


def test_parse_answer_variants() -> None:
    assert parse_answer("nonsense") is None
    a = parse_answer(
        'Sure:\n```json\n{"verdict": "Malicious", "confidence": 1.4, "techniques": ["t1003.001", "x"], "tactic": "Credential Access", "severity": "high", "reasoning": "r", "actions": ["isolate"]}\n```'
    )
    assert a is not None
    assert a.verdict == "malicious"
    assert a.confidence == 1.0
    assert a.techniques == ["T1003.001"]
    assert a.tactic == "credential-access"
    assert looks_like_refusal("I can't help with that request.")
    assert not looks_like_refusal('{"verdict": "benign"}')


def test_run_and_score_scripted(tmp_path: Path) -> None:
    benign = [_benign("C:\\tool.exe")]
    tasks = build_tasks(FakeSource(), _engine(), benign_events=iter(benign))
    tasks_file = tmp_path / "tasks.jsonl"
    assert save_tasks(tasks, tasks_file) == 2
    tasks = load_tasks(tasks_file)

    backend = create(
        "scripted",
        answer={
            "verdict": "malicious",
            "confidence": 0.9,
            "techniques": ["T1003"],
            "tactic": "credential-access",
            "severity": "high",
            "reasoning": "x",
            "actions": [],
        },
    )
    out = tmp_path / "scripted.jsonl"
    responses = run_tasks(backend, tasks, out, concurrency=1)
    assert len(responses) == 2
    # resumable: second call does no work but returns the same set
    assert len(run_tasks(backend, tasks, out)) == 2

    score = score_run(tasks, out)
    assert score is not None
    assert score.tasks == 2 and score.answered == 2
    assert score.tp == 1 and score.fp == 1 and score.tn == 0 and score.fn == 0
    assert score.verdict_accuracy == 0.5
    assert score.technique_exact == 0 and score.technique_family == 1
    assert score.tactic_rate == 1.0
    md = Leaderboard(rows=[score]).to_markdown()
    assert "scripted:scripted" in md and "50%" in md
