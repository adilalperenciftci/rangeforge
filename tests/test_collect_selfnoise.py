from rangeforge.lab.collect import _PS_COLLECT, SELF_MARKER, _is_self_noise


def _record(**data: str) -> dict[str, object]:
    return {"Event": {"System": {"EventID": 4104}, "EventData": data}}


def test_collector_script_is_tagged() -> None:
    assert SELF_MARKER in _PS_COLLECT


def test_self_noise_detection() -> None:
    assert _is_self_noise(_record(ScriptBlockText=f"# {SELF_MARKER}\n$x = 1"))
    assert _is_self_noise(_record(Payload=f"CommandInvocation ... {SELF_MARKER}"))
    assert not _is_self_noise(_record(ScriptBlockText="Get-Process"))
    assert not _is_self_noise({"Event": {"System": {}, "EventData": None}})
