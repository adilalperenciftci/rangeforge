"""Windows event log normalization (Sysmon + Security + PowerShell channels).

Input is the JSON structure produced by the Rust ``evtx`` parser or by the live
collector: ``{"Event": {"System": {...}, "EventData": {...}}}``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from rangeforge.schema.events import (
    Actor,
    Device,
    EventClass,
    File,
    Metadata,
    NetworkEndpoint,
    NormalizedEvent,
    Process,
    Registry,
    Severity,
    User,
)

SYSMON = "Microsoft-Windows-Sysmon"
SECURITY = "Microsoft-Windows-Security-Auditing"
POWERSHELL = "Microsoft-Windows-PowerShell"

# event id -> (class, activity_id, activity_name)
_SYSMON_MAP: dict[int, tuple[EventClass, int, str]] = {
    1: (EventClass.PROCESS_ACTIVITY, 1, "Launch"),
    2: (EventClass.FILE_ACTIVITY, 8, "Set Attributes"),
    3: (EventClass.NETWORK_ACTIVITY, 1, "Open"),
    5: (EventClass.PROCESS_ACTIVITY, 2, "Terminate"),
    6: (EventClass.KERNEL_EXTENSION, 1, "Load"),
    7: (EventClass.MODULE_ACTIVITY, 1, "Load"),
    8: (EventClass.PROCESS_ACTIVITY, 4, "Inject"),
    10: (EventClass.PROCESS_ACTIVITY, 3, "Open"),
    11: (EventClass.FILE_ACTIVITY, 1, "Create"),
    12: (EventClass.REGISTRY_KEY_ACTIVITY, 1, "Create"),
    13: (EventClass.REGISTRY_VALUE_ACTIVITY, 2, "Set"),
    14: (EventClass.REGISTRY_KEY_ACTIVITY, 5, "Rename"),
    15: (EventClass.FILE_ACTIVITY, 1, "Create"),
    17: (EventClass.FILE_ACTIVITY, 1, "Create"),
    18: (EventClass.FILE_ACTIVITY, 3, "Open"),
    22: (EventClass.DNS_ACTIVITY, 1, "Query"),
    23: (EventClass.FILE_ACTIVITY, 4, "Delete"),
    25: (EventClass.PROCESS_ACTIVITY, 4, "Inject"),
    26: (EventClass.FILE_ACTIVITY, 4, "Delete"),
}

_SECURITY_MAP: dict[int, tuple[EventClass, int, str]] = {
    4624: (EventClass.AUTHENTICATION, 1, "Logon"),
    4625: (EventClass.AUTHENTICATION, 1, "Logon"),
    4634: (EventClass.AUTHENTICATION, 2, "Logoff"),
    4648: (EventClass.AUTHENTICATION, 1, "Logon"),
    4672: (EventClass.AUTHENTICATION, 1, "Logon"),
    4688: (EventClass.PROCESS_ACTIVITY, 1, "Launch"),
    4689: (EventClass.PROCESS_ACTIVITY, 2, "Terminate"),
    4697: (EventClass.SCHEDULED_JOB, 1, "Create"),
    4698: (EventClass.SCHEDULED_JOB, 1, "Create"),
    4699: (EventClass.SCHEDULED_JOB, 2, "Delete"),
    4702: (EventClass.SCHEDULED_JOB, 3, "Update"),
    4720: (EventClass.ACCOUNT_CHANGE, 1, "Create"),
    4722: (EventClass.ACCOUNT_CHANGE, 2, "Enable"),
    4724: (EventClass.ACCOUNT_CHANGE, 3, "Password Change"),
    4725: (EventClass.ACCOUNT_CHANGE, 5, "Disable"),
    4726: (EventClass.ACCOUNT_CHANGE, 6, "Delete"),
    4728: (EventClass.ACCOUNT_CHANGE, 7, "Attach Policy"),
    4732: (EventClass.ACCOUNT_CHANGE, 7, "Attach Policy"),
    4738: (EventClass.ACCOUNT_CHANGE, 99, "Other"),
    4756: (EventClass.ACCOUNT_CHANGE, 7, "Attach Policy"),
    4768: (EventClass.AUTHENTICATION, 3, "Authentication Ticket"),
    4769: (EventClass.AUTHENTICATION, 4, "Service Ticket Request"),
    4771: (EventClass.AUTHENTICATION, 3, "Authentication Ticket"),
    4776: (EventClass.AUTHENTICATION, 1, "Logon"),
    4794: (EventClass.ACCOUNT_CHANGE, 3, "Password Change"),
    1102: (EventClass.EVENT_LOG, 3, "Clear"),
}

_LEVEL_TO_SEVERITY = {
    1: Severity.CRITICAL,
    2: Severity.HIGH,
    3: Severity.MEDIUM,
    4: Severity.INFORMATIONAL,
    5: Severity.INFORMATIONAL,
}


def _attr(node: Any, key: str) -> Any:
    if isinstance(node, dict):
        attrs = node.get("#attributes")
        if isinstance(attrs, dict):
            return attrs.get(key)
    return None


def _parse_time(value: Any) -> datetime:
    if isinstance(value, str):
        text = value.strip().replace(" ", "T")
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return datetime.now(tz=UTC)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return datetime.now(tz=UTC)


def _int(value: Any) -> int | None:
    if value is None or value == "" or value == "-":
        return None
    try:
        if isinstance(value, str) and value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except (TypeError, ValueError):
        return None


def _str(value: Any) -> str | None:
    if value is None or value == "-" or value == "":
        return None
    return str(value)


def _hashes(value: Any) -> dict[str, str]:
    text = _str(value)
    if not text:
        return {}
    out: dict[str, str] = {}
    for part in text.split(","):
        if "=" in part:
            algo, digest = part.split("=", 1)
            out[algo.strip().lower()] = digest.strip().lower()
    return out


def _split_user(value: Any) -> User | None:
    text = _str(value)
    if not text:
        return None
    if "\\" in text:
        domain, name = text.split("\\", 1)
        return User(name=name, domain=domain)
    return User(name=text)


def _file_from_image(data: dict[str, Any], key: str = "Image") -> File | None:
    path = _str(data.get(key))
    if not path:
        return None
    return File(
        path=path,
        name=path.rsplit("\\", 1)[-1],
        hashes=_hashes(data.get("Hashes")) if key in ("Image", "ImageLoaded") else {},
        signature_status=_str(data.get("SignatureStatus")) if key == "ImageLoaded" else None,
        company=_str(data.get("Company")),
        description=_str(data.get("Description")),
    )


def _event_id(system: dict[str, Any]) -> int:
    raw = system.get("EventID")
    if isinstance(raw, dict):
        raw = raw.get("#text")
    return _int(raw) or 0


def flatten_record(record: dict[str, Any]) -> dict[str, Any]:
    """Flatten ``System`` + ``EventData`` into one native field map.

    Native names follow the conventions Sigma uses for Windows: EventData keys
    verbatim, plus ``EventID``, ``Channel``, ``Computer``, ``Provider_Name``.
    """
    event = record.get("Event", record)
    system = event.get("System", {}) or {}
    data = event.get("EventData") or event.get("UserData") or {}
    if not isinstance(data, dict):
        data = {}
    # UserData wraps content in a single named child (e.g. EventXML)
    if "EventData" not in event and len(data) == 1:
        inner = next(iter(data.values()))
        if isinstance(inner, dict):
            data = inner

    flat: dict[str, Any] = {}
    for key, value in data.items():
        if key == "#attributes":
            continue
        if isinstance(value, dict) and "#text" in value:
            value = value["#text"]
        flat[key] = value

    flat["EventID"] = _event_id(system)
    flat["Channel"] = system.get("Channel")
    flat["Computer"] = system.get("Computer")
    flat["Provider_Name"] = _attr(system.get("Provider"), "Name")
    flat["Level"] = system.get("Level")
    flat["EventRecordID"] = system.get("EventRecordID")
    flat["TimeCreated"] = _attr(system.get("TimeCreated"), "SystemTime")
    flat["UserID"] = _attr(system.get("Security"), "UserID")
    return flat


def normalize_windows_record(
    record: dict[str, Any],
    *,
    source_file: str | None = None,
    labels: tuple[str, ...] = (),
) -> NormalizedEvent:
    native = flatten_record(record)
    provider = str(native.get("Provider_Name") or "")
    event_id = int(native.get("EventID") or 0)

    if provider == SYSMON:
        mapping = _SYSMON_MAP.get(event_id)
    elif provider == SECURITY or native.get("Channel") == "Security":
        mapping = _SECURITY_MAP.get(event_id)
    else:
        mapping = None
    cls, activity_id, activity_name = mapping or (EventClass.UNKNOWN, 0, "Unknown")

    metadata = Metadata(
        product=provider or str(native.get("Channel") or "windows"),
        log_name=_str(native.get("Channel")),
        original_event_id=str(event_id),
        uid=_str(native.get("EventRecordID")),
        source_file=source_file,
        labels=labels,
    )
    device = Device(hostname=_str(native.get("Computer")), os_type="windows")
    severity = _LEVEL_TO_SEVERITY.get(_int(native.get("Level")) or 4, Severity.INFORMATIONAL)

    event = NormalizedEvent(
        time=_parse_time(native.get("UtcTime") or native.get("TimeCreated")),
        class_uid=cls,
        activity_id=activity_id,
        activity_name=activity_name,
        severity_id=severity,
        metadata=metadata,
        device=device,
        native=native,
        raw=record,
    )
    return _enrich(event, provider, event_id, native)


def _enrich(
    ev: NormalizedEvent, provider: str, event_id: int, d: dict[str, Any]
) -> NormalizedEvent:
    """Fill typed OCSF objects from native fields, by source/event id."""
    updates: dict[str, Any] = {}

    if provider == SYSMON:
        _enrich_sysmon(updates, event_id, d)
    elif provider == SECURITY or d.get("Channel") == "Security":
        _enrich_security(updates, event_id, d)

    return ev.model_copy(update=updates) if updates else ev


def _enrich_sysmon(updates: dict[str, Any], event_id: int, d: dict[str, Any]) -> None:
    actor_user = _split_user(d.get("User"))
    if event_id == 1:
        parent = Process(
            pid=_int(d.get("ParentProcessId")),
            uid=_str(d.get("ParentProcessGuid")),
            cmd_line=_str(d.get("ParentCommandLine")),
            file=_file_from_image(d, "ParentImage"),
            user=_split_user(d.get("ParentUser")),
        )
        updates["process"] = Process(
            pid=_int(d.get("ProcessId")),
            uid=_str(d.get("ProcessGuid")),
            cmd_line=_str(d.get("CommandLine")),
            file=_file_from_image(d),
            user=actor_user,
            integrity=_str(d.get("IntegrityLevel")),
            parent=parent,
        )
        updates["actor"] = Actor(process=parent, user=actor_user)
        return

    if event_id in (8, 10, 25):
        src = Process(
            pid=_int(d.get("SourceProcessId")),
            uid=_str(d.get("SourceProcessGUID") or d.get("SourceProcessGuid")),
            file=_file_from_image(d, "SourceImage"),
        )
        updates["actor"] = Actor(process=src, user=actor_user)
        updates["process"] = Process(
            pid=_int(d.get("TargetProcessId")),
            uid=_str(d.get("TargetProcessGUID") or d.get("TargetProcessGuid")),
            file=_file_from_image(d, "TargetImage"),
        )
        return

    proc = Process(
        pid=_int(d.get("ProcessId")),
        uid=_str(d.get("ProcessGuid")),
        file=_file_from_image(d),
        user=actor_user,
    )
    updates["actor"] = Actor(process=proc, user=actor_user)
    if event_id == 3:
        updates["src_endpoint"] = NetworkEndpoint(
            ip=_str(d.get("SourceIp")),
            port=_int(d.get("SourcePort")),
            hostname=_str(d.get("SourceHostname")),
        )
        updates["dst_endpoint"] = NetworkEndpoint(
            ip=_str(d.get("DestinationIp")),
            port=_int(d.get("DestinationPort")),
            hostname=_str(d.get("DestinationHostname")),
        )
    elif event_id in (6, 7):
        updates["module"] = _file_from_image(d, "ImageLoaded")
    elif event_id in (2, 11, 15, 23, 26):
        path = _str(d.get("TargetFilename"))
        updates["file"] = File(path=path, name=path.rsplit("\\", 1)[-1]) if path else None
    elif event_id in (12, 13, 14):
        updates["registry"] = Registry(key=_str(d.get("TargetObject")), data=_str(d.get("Details")))
    elif event_id == 22:
        updates["dns_query"] = _str(d.get("QueryName"))


def _enrich_security(updates: dict[str, Any], event_id: int, d: dict[str, Any]) -> None:
    subject = User(
        name=_str(d.get("SubjectUserName")),
        domain=_str(d.get("SubjectDomainName")),
        uid=_str(d.get("SubjectUserSid")),
        session_uid=_str(d.get("SubjectLogonId")),
    )
    target = User(
        name=_str(d.get("TargetUserName")),
        domain=_str(d.get("TargetDomainName")),
        uid=_str(d.get("TargetUserSid") or d.get("TargetSid")),
        session_uid=_str(d.get("TargetLogonId")),
    )
    updates["actor"] = Actor(user=subject)
    updates["user"] = target
    if event_id == 4688:
        updates["process"] = Process(
            pid=_int(d.get("NewProcessId")),
            cmd_line=_str(d.get("CommandLine")),
            file=_file_from_image(d, "NewProcessName"),
            parent=Process(
                pid=_int(d.get("ProcessId")),
                file=_file_from_image(d, "ParentProcessName"),
            ),
        )
    elif event_id in (4624, 4625, 4648, 4776):
        updates["src_endpoint"] = NetworkEndpoint(
            ip=_str(d.get("IpAddress")),
            port=_int(d.get("IpPort")),
            hostname=_str(d.get("WorkstationName") or d.get("Workstation")),
        )
        if event_id == 4625:
            updates["severity_id"] = Severity.LOW
    elif event_id == 1102:
        updates["severity_id"] = Severity.HIGH
