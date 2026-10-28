"""Collect posture snapshots from lab hosts and diff them over time."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from rangeforge.lab.inventory import Host, Inventory
from rangeforge.lab.transport import SshTransport, WinRmTransport

INFRA = Path(__file__).resolve().parents[3] / "infra" / "posture"
STATE_DIR = Path("data") / "state" / "posture"


class Snapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    host: str
    os: str
    taken_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    posture: dict[str, Any]


def collect_posture(host: Host, inventory: Inventory | None = None) -> Snapshot:
    if host.os == "windows":
        script = (INFRA / "Get-Posture.ps1").read_text(encoding="utf-8")
        result = WinRmTransport(host).run_script(script)
        if not result.ok:
            raise RuntimeError(f"{host.name}: {result.stderr.strip()[:300]}")
        payload = result.stdout
    else:
        jump = (
            inventory.get(host.ssh.jump_host)
            if (inventory and host.ssh and host.ssh.jump_host)
            else None
        )
        transport = SshTransport(host, jump=jump)
        transport.put(INFRA / "get-posture.sh", "rf-get-posture.sh")  # SFTP cwd is $HOME
        result = transport.run("bash ~/rf-get-posture.sh", sudo=True, timeout=300)
        transport.close()
        if not result.ok:
            raise RuntimeError(f"{host.name}: {result.stderr.strip()[:300]}")
        payload = result.stdout
    start = payload.find("{")
    end = payload.rfind("}")
    if start < 0 or end < 0:
        raise RuntimeError(f"{host.name}: no JSON in posture output")
    return Snapshot(host=host.name, os=host.os, posture=json.loads(payload[start : end + 1]))


def save_snapshot(snapshot: Snapshot, state_dir: Path = STATE_DIR) -> Path:
    folder = state_dir / snapshot.host
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / (snapshot.taken_at.strftime("%Y%m%dT%H%M%SZ") + ".json")
    path.write_text(snapshot.model_dump_json(indent=1), encoding="utf-8")
    return path


def load_snapshots(host: str, state_dir: Path = STATE_DIR) -> list[Snapshot]:
    folder = state_dir / host
    if not folder.exists():
        return []
    return [
        Snapshot.model_validate_json(p.read_text(encoding="utf-8"))
        for p in sorted(folder.glob("*.json"))
    ]


def diff_snapshots(before: Snapshot, after: Snapshot) -> dict[str, tuple[Any, Any]]:
    """Keys whose value changed, excluding the collection timestamp."""
    changed: dict[str, tuple[Any, Any]] = {}
    keys = set(before.posture) | set(after.posture)
    for key in sorted(keys):
        if key == "collected_at":
            continue
        a, b = before.posture.get(key), after.posture.get(key)
        if a != b:
            changed[key] = (a, b)
    return changed
