"""Log ingestion: source-native records -> NormalizedEvent."""

from rangeforge.ingest.evtx import iter_evtx
from rangeforge.ingest.windows import normalize_windows_record

__all__ = ["iter_evtx", "normalize_windows_record"]
