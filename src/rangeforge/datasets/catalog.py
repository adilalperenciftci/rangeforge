"""Dataset abstraction: a catalog of labelled sample files that can be fetched
into the local cache and replayed through the ingest pipeline."""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path

import httpx
from pydantic import BaseModel, ConfigDict

from rangeforge.schema.events import NormalizedEvent

DEFAULT_CACHE = Path("data") / "raw"


class DatasetEntry(BaseModel):
    """One sample file inside a dataset."""

    model_config = ConfigDict(frozen=True)

    dataset: str
    path: str
    """Path inside the upstream repository."""
    url: str
    tactic: str | None = None
    techniques: tuple[str, ...] = ()
    """ATT&CK technique ids, e.g. ``T1003.001``."""
    size: int | None = None

    @property
    def local_name(self) -> str:
        digest = hashlib.sha1(self.path.encode(), usedforsecurity=False).hexdigest()[:8]
        return f"{digest}_{Path(self.path).name}"

    def local_path(self, cache: Path = DEFAULT_CACHE) -> Path:
        return cache / self.dataset / self.local_name

    @property
    def labels(self) -> tuple[str, ...]:
        return self.techniques


class DatasetSource(ABC):
    """A remote dataset we know how to enumerate, fetch and replay."""

    name: str

    def __init__(self, cache: Path = DEFAULT_CACHE) -> None:
        self.cache = cache

    @abstractmethod
    def entries(self) -> list[DatasetEntry]: ...

    @abstractmethod
    def replay(self, entry: DatasetEntry) -> Iterator[NormalizedEvent]: ...

    def fetch(self, entry: DatasetEntry, *, client: httpx.Client | None = None) -> Path:
        target = entry.local_path(self.cache)
        if target.exists() and target.stat().st_size > 0:
            return target
        target.parent.mkdir(parents=True, exist_ok=True)
        own = client is None
        client = client or httpx.Client(timeout=60, follow_redirects=True)
        try:
            with client.stream("GET", entry.url) as resp:
                resp.raise_for_status()
                tmp = target.with_suffix(target.suffix + ".part")
                with tmp.open("wb") as fh:
                    for chunk in resp.iter_bytes():
                        fh.write(chunk)
                tmp.replace(target)
        finally:
            if own:
                client.close()
        return target

    def fetch_all(self, entries: list[DatasetEntry] | None = None) -> list[Path]:
        entries = entries if entries is not None else self.entries()
        with httpx.Client(timeout=60, follow_redirects=True) as client:
            return [self.fetch(e, client=client) for e in entries]
