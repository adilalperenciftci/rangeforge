"""SOC-analyst benchmark: can a model triage real alerts correctly?"""

from rangeforge.bench.score import ModelScore, score_run
from rangeforge.bench.tasks import GroundTruth, TriageTask, build_tasks, load_tasks, save_tasks

__all__ = [
    "GroundTruth",
    "ModelScore",
    "TriageTask",
    "build_tasks",
    "load_tasks",
    "save_tasks",
    "score_run",
]
