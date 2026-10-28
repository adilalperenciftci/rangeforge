"""EVTX-ATTACK-SAMPLES (sbousseaden) - ~300 Windows event log captures of real
attack techniques, organised by ATT&CK tactic.

Upstream: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES (GPL-3.0). We never
redistribute the samples; they are fetched into the local cache on demand.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

import httpx
import yaml

from rangeforge.datasets.catalog import DEFAULT_CACHE, DatasetEntry, DatasetSource
from rangeforge.ingest.evtx import iter_evtx
from rangeforge.schema.events import NormalizedEvent

REPO = "sbousseaden/EVTX-ATTACK-SAMPLES"
BRANCH = "master"
TREE_API = f"https://api.github.com/repos/{REPO}/git/trees/{BRANCH}?recursive=1"
RAW_BASE = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/"

TACTIC_DIRS = {
    "Command and Control": "command-and-control",
    "Credential Access": "credential-access",
    "Defense Evasion": "defense-evasion",
    "Discovery": "discovery",
    "Execution": "execution",
    "Lateral Movement": "lateral-movement",
    "Persistence": "persistence",
    "Privilege Escalation": "privilege-escalation",
    "Other": None,
}

_TECHNIQUE_RE = re.compile(r"(?<![A-Za-z0-9])[Tt](\d{4})(?:[._](\d{3}))?(?![0-9])")

# Filename keywords -> technique ids, for samples whose names carry no T-id.
_KEYWORD_TECHNIQUES: tuple[tuple[str, str], ...] = (
    ("dcsync", "T1003.006"),
    ("mimikatz", "T1003.001"),
    ("lsass", "T1003.001"),
    ("ntds", "T1003.003"),
    ("sam_", "T1003.002"),
    ("kerberoast", "T1558.003"),
    ("asrep", "T1558.004"),
    ("golden", "T1558.001"),
    ("silver", "T1558.002"),
    ("psexec", "T1569.002"),
    ("winrm", "T1021.006"),
    ("rdp", "T1021.001"),
    ("dcom", "T1021.003"),
    ("schtask", "T1053.005"),
    ("schedule", "T1053.005"),
    ("run_key", "T1547.001"),
    ("runkey", "T1547.001"),
    ("bypassuac", "T1548.002"),
    ("injection", "T1055"),
    ("hollowing", "T1055.012"),
    ("sideloading", "T1574.002"),
    ("timestomp", "T1070.006"),
    ("log_clear", "T1070.001"),
    ("1102", "T1070.001"),
    ("powershell", "T1059.001"),
    ("wscript", "T1059.005"),
    ("mshta", "T1218.005"),
    ("rundll32", "T1218.011"),
    ("regsvr32", "T1218.010"),
    ("certutil", "T1105"),
    ("bitsadmin", "T1197"),
    ("wmic", "T1047"),
    ("lolbin", "T1218"),
    ("tunnel", "T1572"),
    ("petitpotam", "T1187"),
    ("petipotam", "T1187"),
    ("printnightmare", "T1068"),
    ("zerologon", "T1068"),
    ("dsrm", "T1098"),
    ("sid_history", "T1134.005"),
    ("sidhistory", "T1134.005"),
    ("named_pipe", "T1134.001"),
    ("namedpipe", "T1134.001"),
    ("wmi_subscription", "T1546.003"),
    ("logon_script", "T1037"),
    ("screensaver", "T1546.002"),
    ("netsh", "T1562.004"),
    ("defender", "T1562.001"),
    ("amsi", "T1562.001"),
    ("ldap", "T1087.002"),
    ("bloodhound", "T1087.002"),
    ("sharphound", "T1087.002"),
    ("net_user", "T1087.001"),
    ("whoami", "T1033"),
    ("process_discovery", "T1057"),
    ("tasklist", "T1057"),
    # generic keywords last: specific matches above win
    ("etw", "T1562.006"),
    ("dns", "T1071.004"),
    ("token", "T1134"),
    ("service", "T1543.003"),
    ("bits", "T1197"),
    ("smb", "T1021.002"),
    ("wmi", "T1047"),
    ("uac", "T1548.002"),
    ("spn", "T1558.003"),
)


_LABELS_FILE = Path(__file__).parent / "labels" / "evtx-attack-samples.yaml"
_curated: dict[str, tuple[str, ...]] | None = None


def curated_labels() -> dict[str, tuple[str, ...]]:
    """Hand-reviewed technique labels for captures whose names carry no id."""
    global _curated
    if _curated is None:
        raw = yaml.safe_load(_LABELS_FILE.read_text(encoding="utf-8")) or {}
        _curated = {str(k): tuple(str(t).upper() for t in v) for k, v in raw.items()}
    return _curated


def techniques_for(path: str) -> tuple[str, ...]:
    """Curated label if one exists, else parsed from the file name."""
    return curated_labels().get(path) or techniques_from_name(Path(path).stem)


def techniques_from_name(name: str) -> tuple[str, ...]:
    found: list[str] = []
    for match in _TECHNIQUE_RE.finditer(name):
        tid = f"T{match.group(1)}"
        if match.group(2):
            tid += f".{match.group(2)}"
        if tid not in found:
            found.append(tid)
    if found:
        return tuple(found)
    lowered = name.lower()
    for keyword, tid in _KEYWORD_TECHNIQUES:
        if keyword in lowered and tid not in found:
            found.append(tid)
    return tuple(found)


class EvtxAttackSamples(DatasetSource):
    name = "evtx-attack-samples"

    def __init__(self, cache: Path = DEFAULT_CACHE) -> None:
        super().__init__(cache)
        self._index = self.cache / self.name / "index.json"

    def _load_tree(self, *, refresh: bool = False) -> list[dict[str, object]]:
        if self._index.exists() and not refresh:
            return list(json.loads(self._index.read_text(encoding="utf-8")))
        headers = {"Accept": "application/vnd.github+json"}
        with httpx.Client(timeout=60, follow_redirects=True, headers=headers) as client:
            resp = client.get(TREE_API)
            resp.raise_for_status()
            tree = [
                {"path": node["path"], "size": node.get("size")}
                for node in resp.json()["tree"]
                if node.get("type") == "blob" and str(node["path"]).lower().endswith(".evtx")
            ]
        self._index.parent.mkdir(parents=True, exist_ok=True)
        self._index.write_text(json.dumps(tree, indent=1), encoding="utf-8")
        return tree

    def entries(self, *, refresh: bool = False) -> list[DatasetEntry]:
        out: list[DatasetEntry] = []
        for node in self._load_tree(refresh=refresh):
            path = str(node["path"])
            top = path.split("/", 1)[0]
            tactic = TACTIC_DIRS.get(top)
            if top not in TACTIC_DIRS and "/" in path:
                continue  # tooling folders, metadata notebooks
            out.append(
                DatasetEntry(
                    dataset=self.name,
                    path=path,
                    url=RAW_BASE + httpx.URL(path).raw_path.decode(),
                    tactic=tactic,
                    techniques=techniques_for(path),
                    size=int(str(node["size"])) if node.get("size") is not None else None,
                )
            )
        return out

    def replay(self, entry: DatasetEntry) -> Iterator[NormalizedEvent]:
        path = self.fetch(entry)
        yield from iter_evtx(path, labels=entry.labels, source_file=entry.path)
