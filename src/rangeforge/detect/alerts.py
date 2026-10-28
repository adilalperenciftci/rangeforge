"""Alert model emitted by the detection engine."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from rangeforge.schema.events import NormalizedEvent


class Alert(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str
    rule_title: str
    level: str
    """Sigma level: informational | low | medium | high | critical."""
    techniques: tuple[str, ...] = ()
    tactics: tuple[str, ...] = ()
    time: datetime
    hostname: str | None = None
    event_uid: str | None = None
    source_file: str | None = None
    labels: tuple[str, ...] = ()
    """Ground-truth labels carried by the triggering event (dataset replay)."""
    summary: str | None = None
    fields: dict[str, object] = Field(default_factory=dict)
    """Key native fields of the triggering event, for triage context."""

    @classmethod
    def from_event(
        cls,
        event: NormalizedEvent,
        *,
        rule_id: str,
        rule_title: str,
        level: str,
        techniques: tuple[str, ...],
        tactics: tuple[str, ...],
        keep_fields: tuple[str, ...],
    ) -> Alert:
        fields = {k: event.native[k] for k in keep_fields if k in event.native}
        return cls(
            rule_id=rule_id,
            rule_title=rule_title,
            level=level,
            techniques=techniques,
            tactics=tactics,
            time=event.time,
            hostname=event.device.hostname,
            event_uid=event.metadata.uid,
            source_file=event.metadata.source_file,
            labels=event.metadata.labels,
            summary=_summarize(event),
            fields=fields,
        )


def _summarize(event: NormalizedEvent) -> str:
    proc = event.process
    if proc and proc.cmd_line:
        return proc.cmd_line[:300]
    if proc and proc.file and proc.file.path:
        return proc.file.path
    if event.file and event.file.path:
        return event.file.path
    if event.registry and event.registry.key:
        return event.registry.key
    if event.dns_query:
        return event.dns_query
    if event.dst_endpoint and event.dst_endpoint.ip:
        return f"-> {event.dst_endpoint.ip}:{event.dst_endpoint.port}"
    if event.user and event.user.name:
        return f"user {event.user.domain or ''}\\{event.user.name}"
    return f"{event.metadata.product} {event.metadata.original_event_id}"
