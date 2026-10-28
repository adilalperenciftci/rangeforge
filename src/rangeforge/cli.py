"""RangeForge command line interface."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import orjson
import typer
from rich.console import Console
from rich.table import Table

from rangeforge import __version__

if TYPE_CHECKING:
    from collections.abc import Iterator

    from rangeforge.bench.runner import TaskResponse
    from rangeforge.detect import DetectionEngine
    from rangeforge.schema.events import NormalizedEvent

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
DEFAULT_RULE_DIRS = (SIGMA_CACHE / "rules" / "windows", Path("rules"))


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


def _load_engine(rule_dirs: list[Path]) -> DetectionEngine:
    from rangeforge.detect import DetectionEngine

    engine = DetectionEngine()
    with console.status(f"Compiling rules from {len(rule_dirs)} path(s)..."):
        engine.load_paths(rule_dirs)
    console.print(
        f"[green]{engine.stats.rules_loaded} rules compiled[/green]"
        + (
            f", {engine.stats.correlations_loaded} correlations"
            if engine.stats.correlations_loaded
            else ""
        )
        + f", {engine.stats.rules_failed} failed"
    )
    return engine


@rules_app.command("stats")
def rules_stats(
    rule_dirs: Annotated[
        list[Path] | None, typer.Argument(help="Rule files/dirs (default: SigmaHQ windows).")
    ] = None,
) -> None:
    """Compile rules and show level/tactic distribution and compile failures."""

    engine = _load_engine(rule_dirs or list(DEFAULT_RULE_DIRS))
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

    engine = _load_engine(rule_dirs or list(DEFAULT_RULE_DIRS))
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


lab_app = typer.Typer(help="Live lab hosts: status, telemetry collection.", no_args_is_help=True)
app.add_typer(lab_app, name="lab")


@lab_app.command("status")
def lab_status(
    inventory_path: Annotated[Path, typer.Option("--inventory", "-i")] = Path("lab.yaml"),
) -> None:
    """Reachability and sensor state of every host in the inventory."""
    from rangeforge.lab import load_inventory
    from rangeforge.lab.collect import AuditdCollector, Bookmarks, WindowsCollector

    inventory = load_inventory(inventory_path)
    marks = Bookmarks.load()
    table = Table(title="lab")
    table.add_column("host")
    table.add_column("os")
    table.add_column("address")
    table.add_column("sensor state")
    for host in inventory.hosts.values():
        try:
            if host.os == "windows":
                counts = WindowsCollector(host, marks).tail_record_ids()
                state = ", ".join(
                    f"{c.split('/')[0].replace('Microsoft-Windows-', '')}={n:,}"
                    for c, n in counts.items()
                )
            elif host.ssh and host.role != "isolated":
                info = AuditdCollector(host, marks, inventory).status()
                state = (
                    f"auditd enabled={info.get('enabled')} "
                    f"rules={info.get('rules')} lost={info.get('lost')}"
                )
            else:
                state = "[dim]not collected[/dim]"
        except Exception as exc:  # unreachable host must not break the table
            state = f"[red]{type(exc).__name__}: {str(exc)[:80]}[/red]"
        table.add_row(host.name, host.os, host.address, state)
    console.print(table)


@lab_app.command("collect")
def lab_collect(
    hosts: Annotated[
        list[str] | None, typer.Argument(help="Host names (default: all sensors).")
    ] = None,
    inventory_path: Annotated[Path, typer.Option("--inventory", "-i")] = Path("lab.yaml"),
    out: Annotated[Path, typer.Option(help="JSONL output directory.")] = Path("data") / "live",
    detect: Annotated[bool, typer.Option(help="Run the Sigma engine on collected events.")] = False,
    rule_dirs: Annotated[list[Path] | None, typer.Option("--rules", "-r")] = None,
) -> None:
    """Pull new telemetry from lab hosts (incremental) into data/live/<host>.jsonl."""
    from rangeforge.lab import load_inventory
    from rangeforge.lab.collect import AuditdCollector, Bookmarks, WindowsCollector, write_jsonl

    inventory = load_inventory(inventory_path)
    marks = Bookmarks.load()
    selected = (
        [inventory.get(h) for h in hosts]
        if hosts
        else [h for h in inventory.hosts.values() if h.role.startswith("sensor")]
    )
    engine = _load_engine(rule_dirs or list(DEFAULT_RULE_DIRS)) if detect else None

    for host in selected:
        collector = (
            WindowsCollector(host, marks)
            if host.os == "windows"
            else AuditdCollector(host, marks, inventory)
        )
        target = out / f"{host.name}.jsonl"
        alerts = 0

        def tap(events: Iterator[NormalizedEvent]) -> Iterator[NormalizedEvent]:
            nonlocal alerts
            for event in events:
                if engine is not None:
                    for alert in engine.evaluate(event):
                        alerts += 1
                        line = (
                            f"[yellow]{alert.level:>8}[/yellow] {alert.rule_title} "
                            f"[dim]{alert.hostname} {', '.join(alert.techniques)}[/dim] "
                            f"{alert.summary or ''}"
                        )
                        console.print(line[:200])
                yield event

        with console.status(f"collecting from {host.name}..."):
            n = write_jsonl(tap(collector.collect()), target)
        marks.save()
        console.print(
            f"[green]{host.name}[/green]: {n:,} new events -> {target}"
            + (f", {alerts} alerts" if detect else "")
        )


bench_app = typer.Typer(help="LLM SOC-analyst benchmark.", no_args_is_help=True)
app.add_typer(bench_app, name="bench")

DEFAULT_TASKS = Path("bench") / "tasks.jsonl"


@bench_app.command("build")
def bench_build(
    rule_dirs: Annotated[list[Path] | None, typer.Option("--rules", "-r")] = None,
    benign: Annotated[
        list[Path] | None,
        typer.Option(help="JSONL of benign live telemetry (from rf lab collect)."),
    ] = None,
    tactic: Annotated[str | None, typer.Option(help="Only this dataset tactic slug.")] = None,
    limit: Annotated[int, typer.Option(help="Max dataset samples (0 = all).")] = 0,
    per_sample: Annotated[int, typer.Option(help="Max tasks per sample / per benign rule.")] = 3,
    out: Annotated[Path, typer.Option()] = DEFAULT_TASKS,
) -> None:
    """Build triage tasks: malicious ones from labelled samples, benign ones from live lab noise."""
    from itertools import chain

    from rangeforge.bench import build_tasks, save_tasks
    from rangeforge.datasets import EvtxAttackSamples
    from rangeforge.lab.collect import read_jsonl

    engine = _load_engine(rule_dirs or list(DEFAULT_RULE_DIRS))
    source = EvtxAttackSamples()
    entries = source.entries()
    if tactic:
        entries = [e for e in entries if e.tactic == tactic]
    entries = [e for e in entries if e.techniques]
    if limit:
        entries = entries[:limit]
    benign_events = chain.from_iterable(read_jsonl(p) for p in benign) if benign else None
    with console.status(f"Building tasks from {len(entries)} samples..."):
        source.fetch_all(entries)
        tasks = build_tasks(
            source, engine, entries=entries, benign_events=benign_events, max_per_sample=per_sample
        )
    n = save_tasks(tasks, out)
    malicious = sum(1 for t in tasks if t.truth.verdict == "malicious")
    console.print(
        f"[green]{n} tasks[/green] ({malicious} malicious, {n - malicious} benign) -> {out}"
    )


@bench_app.command("run")
def bench_run(
    backend: Annotated[
        str,
        typer.Option(
            "--backend",
            "-b",
            help="claude-cli | codex-cli | anthropic | openai | ollama | scripted",
        ),
    ],
    model: Annotated[str | None, typer.Option("--model", "-m")] = None,
    tasks_path: Annotated[Path, typer.Option("--tasks")] = DEFAULT_TASKS,
    limit: Annotated[int, typer.Option(help="Max tasks (0 = all).")] = 0,
    concurrency: Annotated[int, typer.Option("-j")] = 2,
    out_dir: Annotated[Path, typer.Option(help="Where responses land (runs/bench).")] = Path("runs")
    / "bench",
    no_schema: Annotated[
        bool, typer.Option(help="Do not pass a JSON schema to the backend.")
    ] = False,
) -> None:
    """Answer every task with one model. Resumable: re-run to fill gaps."""
    from rangeforge.bench import load_tasks
    from rangeforge.bench.backends import create
    from rangeforge.bench.runner import run_tasks, summarize_errors

    be = create(backend, model)
    tasks = load_tasks(tasks_path)
    if limit:
        tasks = tasks[:limit]
    out = out_dir / f"{be.name}__{be.model.replace('/', '_').replace(':', '_')}.jsonl"
    console.print(f"{be.describe()} on {len(tasks)} tasks -> {out}")

    def progress(resp: TaskResponse, i: int, total: int) -> None:
        if resp.refused:
            status = "refused"
        elif resp.error:
            status = resp.error
        else:
            status = resp.answer.verdict if resp.answer else "?"
        console.print(f"[dim]{i}/{total}[/dim] {resp.task_id} {status} {resp.latency_s:.1f}s")

    responses = run_tasks(
        be, tasks, out, concurrency=concurrency, structured=not no_schema, progress=progress
    )
    console.print(summarize_errors(responses.values()))


@bench_app.command("report")
def bench_report(
    tasks_path: Annotated[Path, typer.Option("--tasks")] = DEFAULT_TASKS,
    runs_dir: Annotated[Path, typer.Option()] = Path("runs") / "bench",
    out: Annotated[Path | None, typer.Option(help="Write leaderboard markdown here.")] = None,
) -> None:
    """Score every response file in runs/bench and print the leaderboard."""
    from rangeforge.bench import load_tasks, score_run
    from rangeforge.bench.score import Leaderboard

    tasks = load_tasks(tasks_path)
    board = Leaderboard()
    for path in sorted(runs_dir.glob("*.jsonl")):
        score = score_run(tasks, path)
        if score:
            board.rows.append(score)
    md = board.to_markdown()
    console.print(md)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        console.print(f"[green]written to {out}")


if __name__ == "__main__":
    app()
