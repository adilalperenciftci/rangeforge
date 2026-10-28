"""RangeForge command line interface."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Annotated

import orjson
import typer
from rich.console import Console
from rich.table import Table

from rangeforge import __version__

app = typer.Typer(
    name="rangeforge",
    help="Detection engineering lab and LLM SOC-analyst benchmark.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
datasets_app = typer.Typer(help="Public labelled telemetry datasets.", no_args_is_help=True)
app.add_typer(datasets_app, name="datasets")
console = Console()


def _version(value: bool) -> None:
    if value:
        console.print(f"rangeforge {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show version.")
    ] = False,
) -> None:
    """RangeForge."""


@app.command()
def ingest(
    path: Annotated[Path, typer.Argument(exists=True, readable=True, help="EVTX file to parse.")],
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write normalized events as JSONL.")
    ] = None,
    limit: Annotated[int, typer.Option(help="Stop after N events (0 = all).")] = 0,
) -> None:
    """Normalize a Windows EVTX file into OCSF-aligned events."""
    from rangeforge.ingest import iter_evtx

    counts: Counter[str] = Counter()
    total = 0
    sink = output.open("wb") if output else None
    try:
        for event in iter_evtx(path):
            total += 1
            counts[f"{event.class_uid.name}/{event.activity_name}"] += 1
            if sink:
                sink.write(orjson.dumps(event.model_dump(mode="json", exclude={"raw"})) + b"\n")
            if limit and total >= limit:
                break
    finally:
        if sink:
            sink.close()

    table = Table(title=f"{path.name}: {total} events")
    table.add_column("class/activity")
    table.add_column("count", justify="right")
    for key, count in counts.most_common():
        table.add_row(key, str(count))
    console.print(table)


@datasets_app.command("list")
def datasets_list(
    tactic: Annotated[str | None, typer.Option(help="Filter by tactic slug.")] = None,
    technique: Annotated[str | None, typer.Option(help="Filter by technique id prefix.")] = None,
    refresh: Annotated[bool, typer.Option(help="Re-fetch the upstream index.")] = False,
) -> None:
    """List samples in EVTX-ATTACK-SAMPLES with their ATT&CK labels."""
    from rangeforge.datasets import EvtxAttackSamples

    entries = EvtxAttackSamples().entries(refresh=refresh)
    if tactic:
        entries = [e for e in entries if e.tactic == tactic]
    if technique:
        entries = [e for e in entries if any(t.startswith(technique) for t in e.techniques)]

    table = Table(title=f"evtx-attack-samples ({len(entries)} files)")
    table.add_column("tactic")
    table.add_column("techniques")
    table.add_column("file")
    table.add_column("KB", justify="right")
    for entry in entries:
        table.add_row(
            entry.tactic or "-",
            ", ".join(entry.techniques) or "[dim]unlabelled[/dim]",
            entry.path,
            f"{(entry.size or 0) // 1024}",
        )
    console.print(table)
    unlabelled = sum(1 for e in entries if not e.techniques)
    console.print(f"[dim]{unlabelled} files without a technique label[/dim]")


@datasets_app.command("pull")
def datasets_pull(
    tactic: Annotated[str | None, typer.Option(help="Only this tactic slug.")] = None,
    limit: Annotated[int, typer.Option(help="Max files (0 = all).")] = 0,
) -> None:
    """Download samples into the local cache (data/raw)."""
    from rangeforge.datasets import EvtxAttackSamples

    source = EvtxAttackSamples()
    entries = source.entries()
    if tactic:
        entries = [e for e in entries if e.tactic == tactic]
    if limit:
        entries = entries[:limit]
    with console.status(f"Fetching {len(entries)} files..."):
        paths = source.fetch_all(entries)
    total = sum(p.stat().st_size for p in paths)
    console.print(f"[green]{len(paths)} files, {total / 1_048_576:.1f} MiB in {source.cache}")


if __name__ == "__main__":
    app()
