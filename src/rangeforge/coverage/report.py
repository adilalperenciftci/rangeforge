"""Aggregate replay results into technique/tactic coverage numbers."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from rangeforge.coverage.replay import ReplayResult, SampleResult, technique_hit


@dataclass
class TechniqueCoverage:
    technique: str
    samples: int = 0
    detected: int = 0
    """Samples where a rule tagged with this technique fired."""
    noisy: int = 0
    """Samples where some rule fired but none tagged with this technique."""
    rules: dict[str, int] = field(default_factory=dict)

    @property
    def rate(self) -> float:
        return self.detected / self.samples if self.samples else 0.0


@dataclass
class TacticCoverage:
    tactic: str
    samples: int = 0
    detected_any: int = 0
    detected_labelled: int = 0

    @property
    def rate_any(self) -> float:
        return self.detected_any / self.samples if self.samples else 0.0


@dataclass
class CoverageSummary:
    samples: int
    labelled: int
    events: int
    alerts: int
    detected_any: int
    detected_labelled: int
    errors: int
    rules_loaded: int
    rules_failed: int
    seconds: float
    techniques: dict[str, TechniqueCoverage]
    tactics: dict[str, TacticCoverage]
    top_rules: list[tuple[str, int]]
    missed: list[SampleResult]
    """Labelled samples where nothing fired at all."""

    @property
    def rate_any(self) -> float:
        return self.detected_any / self.samples if self.samples else 0.0

    @property
    def rate_labelled(self) -> float:
        return self.detected_labelled / self.labelled if self.labelled else 0.0

    @property
    def events_per_second(self) -> float:
        return self.events / self.seconds if self.seconds else 0.0


def summarize(result: ReplayResult) -> CoverageSummary:
    techniques: dict[str, TechniqueCoverage] = {}
    tactics: dict[str, TacticCoverage] = {}
    rule_hits: dict[str, int] = defaultdict(int)
    detected_any = detected_labelled = labelled = alerts = errors = 0
    missed: list[SampleResult] = []

    for sample in result.samples:
        alerts += sample.alerts
        if sample.error:
            errors += 1
        any_hit = sample.detected_any
        label_hit = sample.detected_labelled
        detected_any += any_hit
        if sample.labels:
            labelled += 1
            detected_labelled += label_hit
            if not any_hit:
                missed.append(sample)
        for title, count in sample.rules_fired.items():
            rule_hits[title] += count

        tactic = tactics.setdefault(
            sample.tactic or "unknown", TacticCoverage(sample.tactic or "unknown")
        )
        tactic.samples += 1
        tactic.detected_any += any_hit
        tactic.detected_labelled += label_hit

        fired = set(sample.techniques_fired)
        for label in sample.labels:
            cov = techniques.setdefault(label, TechniqueCoverage(label))
            cov.samples += 1
            hit = technique_hit(label, fired)
            if hit:
                cov.detected += 1
                for title, count in sample.rules_fired.items():
                    cov.rules[title] = cov.rules.get(title, 0) + count
            elif any_hit:
                cov.noisy += 1

    return CoverageSummary(
        samples=len(result.samples),
        labelled=labelled,
        events=result.events,
        alerts=alerts,
        detected_any=detected_any,
        detected_labelled=detected_labelled,
        errors=errors,
        rules_loaded=result.rules_loaded,
        rules_failed=result.rules_failed,
        seconds=result.seconds,
        techniques=dict(sorted(techniques.items())),
        tactics=dict(sorted(tactics.items())),
        top_rules=sorted(rule_hits.items(), key=lambda kv: kv[1], reverse=True)[:25],
        missed=missed,
    )


def to_markdown(summary: CoverageSummary, *, title: str = "Detection coverage") -> str:
    lines = [
        f"# {title}",
        "",
        f"- Samples: **{summary.samples}** ({summary.labelled} with technique labels)",
        f"- Events replayed: **{summary.events:,}** in {summary.seconds:.1f}s "
        f"({summary.events_per_second:,.0f} ev/s)",
        f"- Rules: **{summary.rules_loaded}** loaded, {summary.rules_failed} failed to compile",
        f"- Alerts: **{summary.alerts:,}**",
        f"- Samples with any alert: **{summary.rate_any:.0%}** "
        f"({summary.detected_any}/{summary.samples})",
        f"- Labelled samples where the right technique fired: **{summary.rate_labelled:.0%}** "
        f"({summary.detected_labelled}/{summary.labelled})",
        f"- Samples with parse errors: {summary.errors}",
        "",
        "## By tactic",
        "",
        "| tactic | samples | any alert | right technique |",
        "|---|---:|---:|---:|",
    ]
    for tactic in summary.tactics.values():
        lines.append(
            f"| {tactic.tactic} | {tactic.samples} | {tactic.detected_any} "
            f"({tactic.rate_any:.0%}) | {tactic.detected_labelled} |"
        )
    lines += [
        "",
        "## By technique",
        "",
        "| technique | samples | detected | rate | noisy-only |",
        "|---|---:|---:|---:|---:|",
    ]
    for cov in summary.techniques.values():
        lines.append(
            f"| {cov.technique} | {cov.samples} | {cov.detected} | {cov.rate:.0%} | {cov.noisy} |"
        )
    lines += ["", "## Noisiest rules", "", "| rule | hits |", "|---|---:|"]
    for name, hits in summary.top_rules:
        lines.append(f"| {name} | {hits} |")
    if summary.missed:
        lines += ["", "## Labelled samples with no alert at all", ""]
        for sample in summary.missed:
            lines.append(f"- `{sample.path}` ({', '.join(sample.labels)}, {sample.events} events)")
    return "\n".join(lines) + "\n"
