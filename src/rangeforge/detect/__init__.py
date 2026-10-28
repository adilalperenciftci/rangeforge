"""Detection: Sigma rules compiled to native predicates, streaming engine, correlation."""

from rangeforge.detect.alerts import Alert
from rangeforge.detect.engine import DetectionEngine, EngineStats
from rangeforge.detect.sigma_compiler import CompiledRule, RuleCompileError, compile_rule

__all__ = [
    "Alert",
    "CompiledRule",
    "DetectionEngine",
    "EngineStats",
    "RuleCompileError",
    "compile_rule",
]
