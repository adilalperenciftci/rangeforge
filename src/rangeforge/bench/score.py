# ruff: noqa: E501  (markdown table rows)
"""Score model responses against ground truth and build a leaderboard."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from rangeforge.bench.runner import TaskResponse, load_responses
from rangeforge.bench.tasks import TriageTask
from rangeforge.coverage.replay import technique_hit

SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class ModelScore:
    backend: str
    model: str
    tasks: int = 0
    answered: int = 0
    refused: int = 0
    errors: int = 0

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    technique_exact: int = 0
    """Malicious tasks where at least one predicted technique equals a label."""
    technique_family: int = 0
    """... or is the label's parent / sub-technique."""
    technique_total: int = 0
    tactic_correct: int = 0
    tactic_total: int = 0

    latency_total: float = 0.0
    cost_total: float = 0.0
    cost_known: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    confidence_sum_correct: float = 0.0
    confidence_sum_wrong: float = 0.0
    wrong: int = 0

    # --- derived
    @property
    def verdict_accuracy(self) -> float:
        return (self.tp + self.tn) / self.answered if self.answered else 0.0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def benign_accuracy(self) -> float:
        return self.tn / (self.tn + self.fp) if (self.tn + self.fp) else 0.0

    @property
    def technique_exact_rate(self) -> float:
        return self.technique_exact / self.technique_total if self.technique_total else 0.0

    @property
    def technique_family_rate(self) -> float:
        return self.technique_family / self.technique_total if self.technique_total else 0.0

    @property
    def tactic_rate(self) -> float:
        return self.tactic_correct / self.tactic_total if self.tactic_total else 0.0

    @property
    def mean_latency(self) -> float:
        return self.latency_total / self.answered if self.answered else 0.0

    @property
    def mean_cost(self) -> float | None:
        return self.cost_total / self.cost_known if self.cost_known else None

    @property
    def refusal_rate(self) -> float:
        return self.refused / self.tasks if self.tasks else 0.0

    @property
    def calibration_gap(self) -> float | None:
        """Mean confidence on correct minus mean confidence on wrong verdicts."""
        correct = self.tp + self.tn
        if not correct or not self.wrong:
            return None
        return self.confidence_sum_correct / correct - self.confidence_sum_wrong / self.wrong


def score_responses(
    tasks: Iterable[TriageTask], responses: dict[str, TaskResponse]
) -> ModelScore | None:
    score: ModelScore | None = None
    for task in tasks:
        resp = responses.get(task.id)
        if resp is None:
            continue
        if score is None:
            score = ModelScore(backend=resp.backend, model=resp.model)
        score.tasks += 1
        if resp.refused:
            score.refused += 1
            continue
        if resp.error or resp.answer is None:
            score.errors += 1
            continue
        score.answered += 1
        score.latency_total += resp.latency_s
        if resp.cost_usd is not None:
            score.cost_total += resp.cost_usd
            score.cost_known += 1
        score.input_tokens += resp.input_tokens or 0
        score.output_tokens += resp.output_tokens or 0

        answer = resp.answer
        truth = task.truth
        predicted_malicious = answer.verdict == "malicious"
        actually_malicious = truth.verdict == "malicious"
        correct = predicted_malicious == actually_malicious
        if actually_malicious and predicted_malicious:
            score.tp += 1
        elif actually_malicious:
            score.fn += 1
        elif predicted_malicious:
            score.fp += 1
        else:
            score.tn += 1
        if correct:
            score.confidence_sum_correct += answer.confidence
        else:
            score.wrong += 1
            score.confidence_sum_wrong += answer.confidence

        if actually_malicious and truth.techniques:
            score.technique_total += 1
            predicted = set(answer.techniques)
            if predicted & set(truth.techniques):
                score.technique_exact += 1
                score.technique_family += 1
            elif any(technique_hit(label, predicted) for label in truth.techniques):
                score.technique_family += 1
        if actually_malicious and truth.tactic:
            score.tactic_total += 1
            if answer.tactic and answer.tactic == truth.tactic:
                score.tactic_correct += 1
    return score


def score_run(tasks: list[TriageTask], responses_path: Path) -> ModelScore | None:
    return score_responses(tasks, load_responses(responses_path))


@dataclass
class Leaderboard:
    rows: list[ModelScore] = field(default_factory=list)

    def to_markdown(self) -> str:
        lines = [
            "| model | tasks | verdict acc | F1 | benign acc | technique (exact / family) | tactic | refusals | mean latency | mean cost |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for s in sorted(self.rows, key=lambda r: (r.f1, r.verdict_accuracy), reverse=True):
            cost = f"${s.mean_cost:.4f}" if s.mean_cost is not None else "n/a"
            lines.append(
                f"| {s.backend}:{s.model} | {s.tasks} | {s.verdict_accuracy:.0%} | {s.f1:.2f} | "
                f"{s.benign_accuracy:.0%} | {s.technique_exact_rate:.0%} / {s.technique_family_rate:.0%} | "
                f"{s.tactic_rate:.0%} | {s.refusal_rate:.0%} | {s.mean_latency:.1f}s | {cost} |"
            )
        return "\n".join(lines) + "\n"
