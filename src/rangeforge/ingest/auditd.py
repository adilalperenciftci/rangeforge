"""Linux auditd normalization.

Raw audit log lines (``ausearch --raw`` / ``/var/log/audit/audit.log``) carry
one record per line; records that belong to one kernel event share the same
``msg=audit(<epoch>.<ms>:<serial>)`` id and are grouped here into a single
``NormalizedEvent``.

Native field names follow the Sigma ``linux/auditd`` and
``linux/process_creation`` conventions so SigmaHQ rules run unchanged:
``type``, ``key``, ``syscall``, ``exe``, ``comm``, ``a0``...``aN``, ``cwd``,
``name`` (first PATH item), ``uid``, ``auid``, ``pid``, ``ppid`` and, for
execve, ``Image``, ``CommandLine``, ``ParentImage``-free equivalents used by
process_creation rules (``Image`` = exe, ``CommandLine`` = joined argv).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from typing import Any

from rangeforge.schema.events import (
    Actor,
    Device,
    EventClass,
    File,
    Metadata,
    NormalizedEvent,
    Process,
    Severity,
    User,
)

_HEADER = re.compile(
    r"^type=(?P<type>\S+) msg=audit\((?P<ts>\d+\.\d+):(?P<serial>\d+)\):\s*(?P<body>.*)$"
)
_KV = re.compile(r'(?P<key>[A-Za-z0-9_\-]+)=(?P<val>"(?:[^"\\]|\\.)*"|\S*)')
_HEX = re.compile(r"^[0-9A-Fa-f]+$")

# syscall numbers (x86_64) that matter for classification
_SYSCALL_EXEC = {59, 322}  # execve, execveat
_SYSCALL_NAMES = {
    59: "execve",
    322: "execveat",
    2: "open",
    257: "openat",
    87: "unlink",
    263: "unlinkat",
    82: "rename",
    264: "renameat",
    41: "socket",
    42: "connect",
    49: "bind",
    101: "ptrace",
    105: "setuid",
    106: "setgid",
    117: "setresuid",
    119: "setresgid",
    175: "init_module",
    313: "finit_module",
    176: "delete_module",
}


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    # audit hex-encodes values that contain spaces or non-printables
    if value and _HEX.match(value) and len(value) % 2 == 0 and len(value) >= 4:
        try:
            return bytes.fromhex(value).decode("utf-8", "replace").replace("\x00", " ").strip()
        except ValueError:
            return value
    return value


def parse_record(line: str) -> tuple[str, str, int, dict[str, str]] | None:
    """Parse one raw audit line into (type, timestamp, serial, fields)."""
    m = _HEADER.match(line.strip())
    if not m:
        return None
    fields: dict[str, str] = {}
    for kv in _KV.finditer(m.group("body")):
        key = kv.group("key")
        if key in fields and key != "name":
            continue  # keep the first occurrence (e.g. uid vs UID enrichment)
        fields[key] = _unquote(kv.group("val"))
    return m.group("type"), m.group("ts"), int(m.group("serial")), fields


def group_records(
    lines: Iterable[str],
) -> Iterator[tuple[str, int, list[tuple[str, dict[str, str]]]]]:
    """Group consecutive raw lines by audit event id. Yields (ts, serial, [(type, fields)])."""
    current: tuple[str, int] | None = None
    bucket: list[tuple[str, dict[str, str]]] = []
    for line in lines:
        parsed = parse_record(line)
        if parsed is None:
            continue
        rtype, ts, serial, fields = parsed
        key = (ts, serial)
        if current is not None and key != current:
            yield current[0], current[1], bucket
            bucket = []
        current = key
        bucket.append((rtype, fields))
    if current is not None and bucket:
        yield current[0], current[1], bucket


def _argv(execve: dict[str, str]) -> list[str]:
    try:
        argc = int(execve.get("argc", "0"))
    except ValueError:
        argc = 0
    args: list[str] = []
    for i in range(argc):
        value = execve.get(f"a{i}")
        if value is None:
            # long arguments are split as a1[0], a1[1] ...
            parts = [v for k, v in sorted(execve.items()) if k.startswith(f"a{i}[")]
            value = "".join(parts) if parts else ""
        args.append(value)
    return args


def normalize_audit_event(
    ts: str,
    serial: int,
    records: list[tuple[str, dict[str, str]]],
    *,
    hostname: str | None = None,
    source_file: str | None = None,
    labels: tuple[str, ...] = (),
) -> NormalizedEvent:
    by_type: dict[str, dict[str, str]] = {}
    paths: list[dict[str, str]] = []
    for rtype, fields in records:
        if rtype == "PATH":
            paths.append(fields)
        else:
            by_type.setdefault(rtype, fields)
    paths.sort(key=lambda p: int(p.get("item", "0") or 0))

    syscall = by_type.get("SYSCALL", {})
    execve = by_type.get("EXECVE")
    cwd = by_type.get("CWD", {}).get("cwd")
    primary_type = "SYSCALL" if syscall else next(iter(by_type), records[0][0])
    primary = by_type.get(primary_type, {})

    native: dict[str, Any] = {}
    for rtype, fields in records:
        for k, v in fields.items():
            if rtype == "PATH":
                continue
            native.setdefault(k, v)
    native["type"] = primary_type
    native["serial"] = serial
    if paths:
        native["name"] = paths[0].get("name")
        native["nametype"] = paths[0].get("nametype")
        native["paths"] = [p.get("name") for p in paths]
    if cwd:
        native["cwd"] = cwd

    syscall_nr = int(syscall["syscall"]) if syscall.get("syscall", "").isdigit() else None
    native["syscall_name"] = _SYSCALL_NAMES.get(syscall_nr or -1)

    argv = _argv(execve) if execve else []
    cmd_line = " ".join(argv) if argv else None
    exe = syscall.get("exe")
    if execve or (syscall_nr in _SYSCALL_EXEC):
        cls, activity, name = EventClass.PROCESS_ACTIVITY, 1, "Launch"
        native["Image"] = exe
        native["CommandLine"] = cmd_line
        native["argc"] = len(argv)
    elif primary_type in {
        "USER_LOGIN",
        "USER_AUTH",
        "USER_ACCT",
        "CRED_ACQ",
        "CRED_DISP",
        "USER_START",
        "USER_END",
    }:
        cls, activity, name = EventClass.AUTHENTICATION, 1, "Logon"
    elif primary_type in {
        "ADD_USER",
        "DEL_USER",
        "ADD_GROUP",
        "DEL_GROUP",
        "USER_MGMT",
        "GRP_MGMT",
        "USER_CHAUTHTOK",
    }:
        cls, activity, name = EventClass.ACCOUNT_CHANGE, 99, "Other"
    elif syscall_nr in {41, 42, 49}:
        cls, activity, name = EventClass.NETWORK_ACTIVITY, 1, "Open"
    elif syscall_nr in {175, 313, 176}:
        cls, activity, name = EventClass.KERNEL_EXTENSION, 1, "Load"
    elif paths:
        cls, activity, name = EventClass.FILE_ACTIVITY, 0, "Unknown"
    else:
        cls, activity, name = EventClass.UNKNOWN, 0, "Unknown"

    epoch = float(ts)
    user = User(
        uid=syscall.get("uid") or primary.get("uid"), name=syscall.get("UID") or primary.get("acct")
    )
    proc_file = File(path=exe, name=exe.rsplit("/", 1)[-1]) if exe else None
    process = Process(
        pid=int(syscall["pid"]) if syscall.get("pid", "").isdigit() else None,
        cmd_line=cmd_line,
        file=proc_file,
        user=user,
        parent=Process(pid=int(syscall["ppid"])) if syscall.get("ppid", "").isdigit() else None,
    )
    file = File(path=native.get("name")) if paths and cls is EventClass.FILE_ACTIVITY else None

    return NormalizedEvent(
        time=datetime.fromtimestamp(epoch, tz=UTC),
        class_uid=cls,
        activity_id=activity,
        activity_name=name,
        severity_id=Severity.INFORMATIONAL,
        metadata=Metadata(
            product="auditd",
            log_name="audit",
            original_event_id=primary_type,
            uid=f"{ts}:{serial}",
            source_file=source_file,
            labels=labels,
        ),
        device=Device(hostname=hostname or native.get("node"), os_type="linux"),
        actor=Actor(process=process, user=user),
        process=process if cls is EventClass.PROCESS_ACTIVITY else None,
        file=file,
        native=native,
    )


def iter_audit_lines(
    lines: Iterable[str],
    *,
    hostname: str | None = None,
    source_file: str | None = None,
    labels: tuple[str, ...] = (),
) -> Iterator[NormalizedEvent]:
    for ts, serial, records in group_records(lines):
        yield normalize_audit_event(
            ts, serial, records, hostname=hostname, source_file=source_file, labels=labels
        )
