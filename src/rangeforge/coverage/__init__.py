"""Detection coverage measurement against labelled datasets."""

from rangeforge.coverage.navigator import build_layer
from rangeforge.coverage.replay import ReplayResult, SampleResult, replay_dataset
from rangeforge.coverage.report import CoverageSummary, summarize, to_markdown

__all__ = [
    "CoverageSummary",
    "ReplayResult",
    "SampleResult",
    "build_layer",
    "replay_dataset",
    "summarize",
    "to_markdown",
]
