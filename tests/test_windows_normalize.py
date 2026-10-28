from datetime import UTC, datetime

from rangeforge.ingest.windows import flatten_record, normalize_windows_record
from rangeforge.schema.events import EventClass, Severity


def _record(
    provider: str, event_id: int, channel: str, data: dict[str, object]
) -> dict[str, object]:
    return {
        "Event": {
            "System": {
                "Provider": {"#attributes": {"Name": provider}},
                "EventID": event_id,
                "Level": 4,
                "TimeCreated": {"#attributes": {"SystemTime": "2024-03-01T10:00:00.123456Z"}},
                "EventRecordID": 42,
                "Channel": channel,
                "Computer": "WS01.lab.local",
                "Security": {"#attributes": {"UserID": "S-1-5-18"}},
            },
            "EventData": data,
        }
    }


SYSMON_1 = _record(
    "Microsoft-Windows-Sysmon",
    1,
    "Microsoft-Windows-Sysmon/Operational",
    {
        "UtcTime": "2024-03-01 10:00:00.100",
        "ProcessGuid": "{1}",
        "ProcessId": 1234,
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "User": "LAB\\alice",
        "IntegrityLevel": "Medium",
        "Hashes": "SHA256=AB,MD5=CD",
        "ParentProcessGuid": "{0}",
        "ParentProcessId": 1000,
        "ParentImage": "C:\\Windows\\explorer.exe",
        "ParentCommandLine": "explorer.exe",
    },
)


def test_flatten_merges_system_and_eventdata() -> None:
    flat = flatten_record(SYSMON_1)
    assert flat["EventID"] == 1
    assert flat["Channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert flat["Provider_Name"] == "Microsoft-Windows-Sysmon"
    assert flat["Image"].endswith("cmd.exe")


def test_sysmon_process_create() -> None:
    ev = normalize_windows_record(SYSMON_1, source_file="x.evtx", labels=("T1059.003",))
    assert ev.class_uid is EventClass.PROCESS_ACTIVITY
    assert ev.activity_name == "Launch"
    assert ev.type_uid == 100701
    assert ev.category_uid == 1
    assert ev.time == datetime(2024, 3, 1, 10, 0, 0, 100000, tzinfo=UTC)
    assert ev.process is not None and ev.process.pid == 1234
    assert ev.process.file is not None and ev.process.file.name == "cmd.exe"
    assert ev.process.file.hashes == {"sha256": "ab", "md5": "cd"}
    assert ev.process.user is not None and ev.process.user.domain == "LAB"
    assert ev.process.parent is not None and ev.process.parent.pid == 1000
    assert ev.actor.process is ev.process.parent
    assert ev.metadata.labels == ("T1059.003",)
    assert ev.field("commandline") == "cmd.exe /c whoami"


def test_security_logon_failure() -> None:
    rec = _record(
        "Microsoft-Windows-Security-Auditing",
        4625,
        "Security",
        {
            "SubjectUserName": "-",
            "TargetUserName": "bob",
            "TargetDomainName": "LAB",
            "IpAddress": "10.0.0.5",
            "IpPort": "51515",
            "LogonType": 3,
            "Status": "0xc000006d",
        },
    )
    ev = normalize_windows_record(rec)
    assert ev.class_uid is EventClass.AUTHENTICATION
    assert ev.severity_id is Severity.LOW
    assert ev.user is not None and ev.user.name == "bob"
    assert ev.actor.user is not None and ev.actor.user.name is None
    assert ev.src_endpoint is not None and ev.src_endpoint.port == 51515
    assert ev.time == datetime(2024, 3, 1, 10, 0, 0, 123456, tzinfo=UTC)


def test_unknown_provider_still_normalizes() -> None:
    rec = _record("Some-Vendor", 9999, "Application", {"Payload": "x"})
    ev = normalize_windows_record(rec)
    assert ev.class_uid is EventClass.UNKNOWN
    assert ev.native["Payload"] == "x"
    assert ev.device.hostname == "WS01.lab.local"
