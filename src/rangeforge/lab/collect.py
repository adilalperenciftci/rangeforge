# ruff: noqa: E501  (embedded PowerShell is kept readable on long lines)
"""Pull telemetry from lab hosts into NormalizedEvents, incrementally.

Windows: a PowerShell snippet reads events newer than the last RecordId per
channel and emits them as JSON in the same ``{"Event": {"System", "EventData"}}``
shape the EVTX reader produces, so one normalizer serves both paths.

Linux: ``ausearch --raw`` since the last seen audit timestamp, grouped and
normalized by the auditd ingester.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import orjson
from pydantic import BaseModel, Field

from rangeforge.ingest.auditd import iter_audit_lines
from rangeforge.ingest.windows import normalize_windows_record
from rangeforge.lab.inventory import Host, Inventory
from rangeforge.lab.transport import SshTransport, WinRmTransport
from rangeforge.schema.events import NormalizedEvent

DEFAULT_CHANNELS = (
    "Microsoft-Windows-Sysmon/Operational",
    "Security",
    "Microsoft-Windows-PowerShell/Operational",
)
STATE_FILE = Path("data") / "state" / "bookmarks.json"


class Bookmarks(BaseModel):
    """Per host/channel high-water marks so collection is incremental."""

    windows: dict[str, dict[str, int]] = Field(default_factory=dict)
    """host -> channel -> last RecordId."""
    linux: dict[str, str] = Field(default_factory=dict)
    """host -> last audit event id ``<epoch>.<ms>:<serial>``."""

    @classmethod
    def load(cls, path: Path = STATE_FILE) -> Bookmarks:
        if path.exists():
            return cls.model_validate_json(path.read_text(encoding="utf-8"))
        return cls()

    def save(self, path: Path = STATE_FILE) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=1), encoding="utf-8")


# PowerShell: read events after a RecordId and print one JSON object per line
# in the evtx-parser shape. Values are strings, which is what EventData holds.
# Every script we run on a target carries this marker so the collector can drop
# the PowerShell script-block / module events it generates itself. Without it,
# script-block logging turns each collection round into new events for the next.
SELF_MARKER = "rangeforge-collector"

_PS_COLLECT = r"""
# rangeforge-collector
$ErrorActionPreference = 'Stop'
$channel = '{channel}'
$since = {since}
$max = {max}
$filter = "*[System[EventRecordID > $since]]"
try {{
  $events = Get-WinEvent -LogName $channel -FilterXPath $filter -MaxEvents $max -Oldest -ErrorAction Stop
}} catch {{
  if ($_.Exception.Message -match 'No events were found') {{ $events = @() }} else {{ throw }}
}}
$sb = New-Object System.Text.StringBuilder
foreach ($e in $events) {{
  $x = [xml]$e.ToXml()
  $sys = $x.Event.System
  $data = [ordered]@{{}}
  if ($x.Event.EventData) {{
    foreach ($d in $x.Event.EventData.Data) {{
      if ($d.Name) {{ $data[$d.Name] = [string]$d.'#text' }}
    }}
  }} elseif ($x.Event.UserData) {{
    $inner = $x.Event.UserData.FirstChild
    foreach ($n in $inner.ChildNodes) {{ $data[$n.LocalName] = [string]$n.InnerText }}
  }}
  $rec = [ordered]@{{
    Event = [ordered]@{{
      System = [ordered]@{{
        Provider = @{{ '#attributes' = @{{ Name = $sys.Provider.Name; Guid = $sys.Provider.Guid }} }}
        EventID = [int]$e.Id
        Version = [int]$sys.Version
        Level = [int]$sys.Level
        Task = [int]$sys.Task
        Opcode = [int]$sys.Opcode
        Keywords = [string]$sys.Keywords
        TimeCreated = @{{ '#attributes' = @{{ SystemTime = $e.TimeCreated.ToUniversalTime().ToString('o') }} }}
        EventRecordID = [long]$e.RecordId
        Execution = @{{ '#attributes' = @{{ ProcessID = [int]$e.ProcessId; ThreadID = [int]$e.ThreadId }} }}
        Channel = $e.LogName
        Computer = $e.MachineName
        Security = @{{ '#attributes' = @{{ UserID = [string]$e.UserId }} }}
      }}
      EventData = $data
    }}
  }}
  [void]$sb.AppendLine(($rec | ConvertTo-Json -Compress -Depth 6))
}}
Write-Output $sb.ToString()
"""


def _iter_json_lines(text: str) -> Iterator[dict[str, Any]]:
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield orjson.loads(line)
        except orjson.JSONDecodeError:
            continue


def _is_self_noise(record: dict[str, Any]) -> bool:
    """True for PowerShell logging events produced by the collector's own scripts."""
    data = record.get("Event", {}).get("EventData") or {}
    for key in ("ScriptBlockText", "Payload", "ContextInfo"):
        value = data.get(key)
        if isinstance(value, str) and SELF_MARKER in value:
            return True
    return False


class WindowsCollector:
    def __init__(
        self, host: Host, bookmarks: Bookmarks, *, batch: int = 5000, drop_self_noise: bool = True
    ) -> None:
        self.host = host
        self.bookmarks = bookmarks
        self.batch = batch
        self.drop_self_noise = drop_self_noise
        self.transport = WinRmTransport(host)

    def channels(self) -> tuple[str, ...]:
        return self.host.channels or DEFAULT_CHANNELS

    def collect(self, *, channels: tuple[str, ...] | None = None) -> Iterator[NormalizedEvent]:
        marks = self.bookmarks.windows.setdefault(self.host.name, {})
        for channel in channels or self.channels():
            since = marks.get(channel, 0)
            while True:
                script = _PS_COLLECT.format(channel=channel, since=since, max=self.batch)
                result = self.transport.run_ps(script)
                if not result.ok:
                    raise RuntimeError(f"{self.host.name}/{channel}: {result.stderr.strip()[:300]}")
                count = 0
                for record in _iter_json_lines(result.stdout):
                    count += 1
                    rid = int(record["Event"]["System"]["EventRecordID"])
                    since = max(since, rid)
                    if self.drop_self_noise and _is_self_noise(record):
                        continue
                    yield normalize_windows_record(
                        record, source_file=f"{self.host.name}:{channel}"
                    )
                marks[channel] = since
                if count < self.batch:
                    break

    def tail_record_ids(self) -> dict[str, int]:
        """Current newest RecordId per channel (for ``status``)."""
        names = ",".join(f"'{c}'" for c in self.channels())
        script = (
            f"foreach ($c in @({names})) {{ $l = Get-WinEvent -ListLog $c -ErrorAction SilentlyContinue; "
            "if ($l) { @{ c = $c; n = $l.RecordCount } | ConvertTo-Json -Compress } }"
        )
        result = self.transport.run_ps(script)
        out: dict[str, int] = {}
        for item in _iter_json_lines(result.stdout):
            out[str(item["c"])] = int(item["n"] or 0)
        return out


class AuditdCollector:
    def __init__(
        self, host: Host, bookmarks: Bookmarks, inventory: Inventory | None = None
    ) -> None:
        self.host = host
        self.bookmarks = bookmarks
        jump = None
        if host.ssh and host.ssh.jump_host and inventory:
            jump = inventory.get(host.ssh.jump_host)
        self.transport = SshTransport(host, jump=jump)

    def collect(self) -> Iterator[NormalizedEvent]:
        last = self.bookmarks.linux.get(self.host.name)
        if last:
            # ausearch parses -ts with the remote locale and time zone; pin both
            # to UTC on both sides so the window is exact regardless of the
            # operator's or the target's zone.
            epoch = float(last.split(":")[0])
            start = datetime.fromtimestamp(epoch, tz=UTC)
            when = f"-ts {start.strftime('%m/%d/%y %H:%M:%S')}"  # C-locale form
        else:
            when = "-ts today"
        result = self.transport.run(
            f"env TZ=UTC LC_ALL=C ausearch --raw --input-logs {when}", sudo=True
        )
        if result.code not in (0, 1):  # 1 = no matches
            raise RuntimeError(f"{self.host.name}: {result.stderr.strip()[:300]}")
        last_seen = last
        for event in iter_audit_lines(result.stdout.splitlines(), hostname=self.host.name):
            uid = event.metadata.uid or ""
            if last and uid <= last and uid.split(":")[0] == last.split(":")[0]:
                continue  # same second as the bookmark and already seen
            if last and float(uid.split(":")[0]) < float(last.split(":")[0]):
                continue
            last_seen = max(last_seen or "", uid)
            yield event
        if last_seen:
            self.bookmarks.linux[self.host.name] = last_seen

    def status(self) -> dict[str, Any]:
        result = self.transport.run("auditctl -s", sudo=True)
        info: dict[str, Any] = {}
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                info[parts[0]] = parts[1]
        rules = self.transport.run("auditctl -l | wc -l", sudo=True)
        info["rules"] = rules.stdout.strip()
        return info


def write_jsonl(events: Iterator[NormalizedEvent], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("ab") as fh:
        for event in events:
            fh.write(orjson.dumps(event.model_dump(mode="json", exclude={"raw"})) + b"\n")
            n += 1
    return n


def read_jsonl(path: Path) -> Iterator[NormalizedEvent]:
    with path.open("rb") as fh:
        for line in fh:
            if line.strip():
                yield NormalizedEvent.model_validate(json.loads(line))
