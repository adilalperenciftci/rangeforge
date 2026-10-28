"""ATT&CK Navigator layer export (v4.5 layer format)."""

from __future__ import annotations

from typing import Any

from rangeforge.coverage.report import CoverageSummary

LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.1.0"
ATTACK_VERSION = "16"


def build_layer(
    summary: CoverageSummary,
    *,
    name: str = "RangeForge detection coverage",
    description: str = (
        "Share of labelled samples per technique where a correctly tagged rule fired."
    ),
) -> dict[str, Any]:
    techniques: list[dict[str, Any]] = []
    for cov in summary.techniques.values():
        score = round(cov.rate * 100)
        techniques.append(
            {
                "techniqueID": cov.technique,
                "score": score,
                "comment": f"{cov.detected}/{cov.samples} samples detected; "
                + (
                    ", ".join(
                        f"{r} ({n})"
                        for r, n in sorted(cov.rules.items(), key=lambda kv: -kv[1])[:5]
                    )
                    or "no matching rule"
                ),
                "enabled": True,
                "showSubtechniques": "." in cov.technique,
            }
        )
    return {
        "name": name,
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": description,
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ff6666ff", "#ffe766ff", "#8ec843ff"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "0% of samples detected", "color": "#ff6666ff"},
            {"label": "100% of samples detected", "color": "#8ec843ff"},
        ],
        "metadata": [
            {"name": "samples", "value": str(summary.samples)},
            {"name": "rules", "value": str(summary.rules_loaded)},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }
