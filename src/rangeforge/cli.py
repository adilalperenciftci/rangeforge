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


rules_app = typer.Typer(help="Sigma rule management.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")
coverage_app = typer.Typer(help="Detection coverage measurement.", no_args_is_help=True)
app.add_typer(coverage_app, name="coverage")

SIGMA_CACHE = Path("data") / "cache" / "sigma"
DEFAULT_RULE_DIRS = (SIGMA_CACHE / "rules" / "windows",)


@rules_app.command("pull")
def rules_pull(
    refresh: Annotated[bool, typer.Option(help="Update an existing checkout.")] = False,
) -> None:
    """Sparse-clone SigmaHQ/sigma rules into the local cache."""
    import subprocess

    if SIGMA_CACHE.exists():
        if refresh:
            subprocess.run(["git", "-C", str(SIGMA_CACHE), "pull", "-q"], check=True)
            console.print("[green]updated")
        else:
            console.print(f"{SIGMA_CACHE} already present (use --refresh to update)")
        return
    SIGMA_CACHE.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--sparse",
            "https://github.com/SigmaHQ/sigma", str(SIGMA_CACHE),
        ],
        check=True,
    )  # fmt: skip
    subprocess.run(
        [
            "git", "-C", str(SIGMA_CACHE), "sparse-checkout", "set", "--no-cone",
            "rules/windows", "rules/linux", "rules-emerging-threats", "rules-threat-hunting",
        ],
        check=True,
    )  # fmt: skip
    console.print(f"[green]SigmaHQ rules checked out to {SIGMA_CACHE}")


def _load_engine(rule_dirs: list[Path]) -> object:
    from rangeforge.detect import DetectionEngine

    engine = DetectionEngine()
    with console.status(f"Compiling rules from {len(rule_dirs)} path(s)..."):
        engine.load_paths(rule_dirs)
    console.print(
        f"[green]{engine.stats.rules_loaded} rules compiled[/green], "
        f"{engine.stats.rules_failed} failed"
    )
    return engine


@rules_app.command("stats")
def rules_stats(
    rule_dirs: Annotated[
        list[Path] | None, typer.Argument(help="Rule files/dirs (default: SigmaHQ windows).")
    ] = None,
) -> None:
    """Compile rules and show level/tactic distribution and compile failures."""
    from rangeforge.detect import DetectionEngine

    engine = _load_engine(rule_dirs or list(DEFAULT_RULE_DIRS))
    assert isinstance(engine, DetectionEngine)
    levels: Counter[str] = Counter(r.level for r in engine.rules)
    tactics: Counter[str] = Counter(t for r in engine.rules for t in r.tactics)
    unrestricted = sum(1 for r in engine.rules if r.event_filter.unrestricted)
    table = Table(title="rules by level")
    table.add_column("level")
    table.add_column("count", justify="right")
    for level, count in levels.most_common():
        table.add_row(level, str(count))
    console.print(table)
    table = Table(title="rules by tactic")
    table.add_column("tactic")
    table.add_column("count", justify="right")
    for tactic, count in tactics.most_common():
        table.add_row(tactic, str(count))
    console.print(table)
    console.print(f"{unrestricted} rules without a logsource filter (evaluated on every event)")
    for source, reason in list(engine.stats.failures.items())[:20]:
        console.print(f"[red]{Path(source).name}[/red]: {reason[:140]}")


@coverage_app.command("run")
def coverage_run(
    rule_dirs: Annotated[
        list[Path] | None, typer.Option("--rules", "-r", help="Rule files/dirs.")
    ] = None,
    tactic: Annotated[str | None, typer.Option(help="Only this dataset tactic slug.")] = None,
    limit: Annotated[int, typer.Option(help="Max samples (0 = all).")] = 0,
    out: Annotated[Path | None, typer.Option(help="Output directory (default runs/<ts>).")] = None,
    alerts: Annotated[bool, typer.Option(help="Also write every alert to alerts.jsonl.")] = True,
) -> None:
    """Replay EVTX-ATTACK-SAMPLES through the rules and measure ATT&CK coverage."""
    from datetime import UTC, datetime

    from rangeforge.coverage import build_layer, replay_dataset, summarize, to_markdown
    from rangeforge.datasets import EvtxAttackSamples
    from rangeforge.detect import DetectionEngine

    engine = _load_engine(rule_dirs or list(DEFAULT_RULE_DIRS))
    assert isinstance(engine, DetectionEngine)
    source = EvtxAttackSamples()
    entries = source.entries()
    if tactic:
        entries = [e for e in entries if e.tactic == tactic]
    if limit:
        entries = entries[:limit]
    out = out or Path("runs") / datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
    out.mkdir(parents=True, exist_ok=True)

    alert_file = (out / "alerts.jsonl").open("wb") if alerts else None

    def sink(alert: object) -> None:
        if alert_file:
            alert_file.write(orjson.dumps(alert.model_dump(mode="json")) + b"\n")  # type: ignore[attr-defined]

    with console.status("Fetching samples...") as status:
        source.fetch_all(entries)
        status.update(f"Replaying {len(entries)} samples...")

        def progress(result: object) -> None:
            status.update(
                f"[{result.path}] {result.events} events, {result.alerts} alerts"  # type: ignore[attr-defined]
            )

        result = replay_dataset(source, engine, entries=entries, alert_sink=sink, progress=progress)
    if alert_file:
        alert_file.close()

    summary = summarize(result)
    result.write_jsonl(out / "samples.jsonl")
    (out / "summary.md").write_text(to_markdown(summary), encoding="utf-8")
    (out / "navigator-layer.json").write_bytes(
        orjson.dumps(build_layer(summary), option=orjson.OPT_INDENT_2)
    )

    table = Table(title="coverage")
    table.add_column("metric")
    table.add_column("value", justify="right")
    table.add_row("samples", str(summary.samples))
    table.add_row("events", f"{summary.events:,}")
    table.add_row("events/s", f"{summary.events_per_second:,.0f}")
    table.add_row("alerts", f"{summary.alerts:,}")
    table.add_row("any alert", f"{summary.rate_any:.0%}")
    table.add_row("right technique", f"{summary.rate_labelled:.0%} of {summary.labelled} labelled")
    console.print(table)
    console.print(f"[green]report written to {out}")


if __name__ == "__main__":
    app()
