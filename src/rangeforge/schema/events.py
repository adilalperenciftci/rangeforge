"""OCSF-aligned normalized event model.

RangeForge keeps two views of every event:

* ``NormalizedEvent`` - a typed, OCSF-aligned structure used by correlation,
  storage and reporting.
* ``NormalizedEvent.native`` - the flat, source-native field map (Sysmon
  ``Image``, Security ``TargetUserName`` ...). Sigma rules are written against
  native names, so the detection engine matches on this view directly instead of
  lossy re-mapping.

Only the subset of OCSF we actually need is modelled; everything else survives
in ``native`` and ``raw``.
"""

from __future__ import annotations

from datetime import datetime
from enum import IntEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventClass(IntEnum):
    """OCSF class_uid values used by RangeForge."""

    UNKNOWN = 0
    FILE_ACTIVITY = 1001
    KERNEL_EXTENSION = 1002
    MEMORY_ACTIVITY = 1004
    MODULE_ACTIVITY = 1005
    SCHEDULED_JOB = 1006
    PROCESS_ACTIVITY = 1007
    EVENT_LOG = 1008
    ACCOUNT_CHANGE = 3001
    AUTHENTICATION = 3002
    NETWORK_ACTIVITY = 4001
    DNS_ACTIVITY = 4003
    REGISTRY_KEY_ACTIVITY = 201001
    REGISTRY_VALUE_ACTIVITY = 201002


class Severity(IntEnum):
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Metadata(_Model):
    product: str
    """Log producer, e.g. ``Microsoft-Windows-Sysmon`` or ``auditd``."""
    version: str | None = None
    log_name: str | None = None
    """Channel / file the event came from."""
    original_event_id: str | None = None
    uid: str | None = None
    """Stable id of the record inside its source (EventRecordID, audit serial)."""
    source_file: str | None = None
    """Dataset file the record was replayed from, if any."""
    labels: tuple[str, ...] = ()
    """Ground-truth labels attached by a dataset (ATT&CK technique ids)."""


class Device(_Model):
    hostname: str | None = None
    os_type: str | None = None
    ip: str | None = None


class User(_Model):
    name: str | None = None
    domain: str | None = None
    uid: str | None = None
    """SID on Windows, uid on Linux."""
    session_uid: str | None = None
    """Logon id on Windows."""


class File(_Model):
    path: str | None = None
    name: str | None = None
    hashes: dict[str, str] = Field(default_factory=dict)
    signature_status: str | None = None
    company: str | None = None
    description: str | None = None


class Process(_Model):
    pid: int | None = None
    uid: str | None = None
    """Process GUID on Sysmon."""
    cmd_line: str | None = None
    file: File | None = None
    user: User | None = None
    integrity: str | None = None
    parent: Process | None = None
    created_time: datetime | None = None


class Actor(_Model):
    process: Process | None = None
    user: User | None = None


class NetworkEndpoint(_Model):
    ip: str | None = None
    port: int | None = None
    hostname: str | None = None


class Registry(_Model):
    key: str | None = None
    value_name: str | None = None
    data: str | None = None


class NormalizedEvent(_Model):
    """One normalized security event."""

    time: datetime
    class_uid: EventClass
    activity_id: int = 0
    activity_name: str = "Unknown"
    severity_id: Severity = Severity.INFORMATIONAL
    metadata: Metadata
    device: Device = Field(default_factory=Device)
    actor: Actor = Field(default_factory=Actor)

    process: Process | None = None
    file: File | None = None
    module: File | None = None
    registry: Registry | None = None
    src_endpoint: NetworkEndpoint | None = None
    dst_endpoint: NetworkEndpoint | None = None
    user: User | None = None
    """Target user for auth / account change classes."""
    dns_query: str | None = None
    message: str | None = None

    native: dict[str, Any] = Field(default_factory=dict)
    """Flat source-native fields. Detection rules evaluate against this map."""
    raw: dict[str, Any] | None = Field(default=None, repr=False)

    @property
    def category_uid(self) -> int:
        return int(self.class_uid) // 1000

    @property
    def type_uid(self) -> int:
        return int(self.class_uid) * 100 + self.activity_id

    def field(self, name: str, default: Any = None) -> Any:
        """Look up a native field, case-insensitively as a fallback."""
        if name in self.native:
            return self.native[name]
        lowered = name.lower()
        for key, value in self.native.items():
            if key.lower() == lowered:
                return value
        return default
