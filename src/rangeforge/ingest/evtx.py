"""EVTX file ingestion using the Rust-backed ``evtx`` parser."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import orjson
from evtx import PyEvtxParser

from rangeforge.ingest.windows import normalize_windows_record
from rangeforge.schema.events import NormalizedEvent


def iter_evtx_records(path: Path) -> Iterator[dict[str, Any]]:
    parser = PyEvtxParser(str(path))
    for record in parser.records_json():
        payload = record.get("data") if isinstance(record, dict) else None
        if not payload:
            continue
        try:
            yield orjson.loads(payload)
        except orjson.JSONDecodeError:
            continue


def iter_evtx(
    path: Path,
    *,
    labels: tuple[str, ...] = (),
    source_file: str | None = None,
) -> Iterator[NormalizedEvent]:
    """Yield normalized events from an ``.evtx`` file, in file order."""
    name = source_file or path.name
    for record in iter_evtx_records(path):
        yield normalize_windows_record(record, source_file=name, labels=labels)
