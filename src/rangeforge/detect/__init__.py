"""Detection: Sigma rules compiled to native predicates, streaming engine, correlation."""

from rangeforge.detect.alerts import Alert
from rangeforge.detect.correlation import CompiledCorrelation, compile_correlation
from rangeforge.detect.engine import DetectionEngine, EngineStats
from rangeforge.detect.sigma_compiler import CompiledRule, RuleCompileError, compile_rule

__all__ = [
    "Alert",
    "CompiledCorrelation",
    "CompiledRule",
    "DetectionEngine",
    "EngineStats",
    "RuleCompileError",
    "compile_correlation",
    "compile_rule",
]
