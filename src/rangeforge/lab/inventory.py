"""Lab inventory loaded from ``lab.yaml`` (+ optional ``lab.local.yaml`` overrides).

Secrets never live in the YAML: SSH uses a key file path, Windows uses a
DPAPI-protected ``Export-Clixml`` credential file that only the exporting user
account can decrypt.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

DEFAULT_INVENTORY = Path("lab.yaml")
LOCAL_OVERRIDE = Path("lab.local.yaml")


class SshAuth(BaseModel):
    model_config = ConfigDict(frozen=True)
    user: str
    key_file: Path
    port: int = 22
    jump_host: str | None = None
    """Name of another inventory host to tunnel through."""


class WinRmAuth(BaseModel):
    model_config = ConfigDict(frozen=True)
    credential_file: Path
    """``Export-Clixml`` PSCredential file (DPAPI, current user)."""
    port: int = 5985
    transport: Literal["ntlm", "basic", "kerberos"] = "ntlm"


class Host(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    address: str
    os: Literal["windows", "linux"]
    role: str = "target"
    vm_name: str | None = None
    """Hyper-V VM name, for checkpoint/restore."""
    ssh: SshAuth | None = None
    winrm: WinRmAuth | None = None
    channels: tuple[str, ...] = ()
    """Windows event channels to collect (defaults applied by the collector)."""
    tags: tuple[str, ...] = ()


class Inventory(BaseModel):
    model_config = ConfigDict(frozen=True)

    hosts: dict[str, Host] = Field(default_factory=dict)

    def by_os(self, os_name: str) -> list[Host]:
        return [h for h in self.hosts.values() if h.os == os_name]

    def get(self, name: str) -> Host:
        try:
            return self.hosts[name]
        except KeyError as exc:
            raise KeyError(f"unknown host {name!r}; known: {sorted(self.hosts)}") from exc


def _deep_merge(base: dict[str, object], override: dict[str, object]) -> dict[str, object]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)  # type: ignore[arg-type]
        else:
            out[key] = value
    return out


def load_inventory(
    path: Path = DEFAULT_INVENTORY, local: Path | None = LOCAL_OVERRIDE
) -> Inventory:
    data: dict[str, object] = {}
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if local and local.exists():
        data = _deep_merge(data, yaml.safe_load(local.read_text(encoding="utf-8")) or {})
    hosts_raw = data.get("hosts", {})
    if not isinstance(hosts_raw, dict):
        raise ValueError("lab.yaml: 'hosts' must be a mapping")
    hosts = {name: Host(name=name, **spec) for name, spec in hosts_raw.items()}
    return Inventory(hosts=hosts)
