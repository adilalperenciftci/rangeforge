# ruff: noqa: E501  (prompt text and schema descriptions read better unwrapped)
"""Prompt and answer schema shared by every backend."""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

SYSTEM_PROMPT = """You are a senior SOC analyst performing alert triage for a security operations team.

You receive one detection alert (from a Sigma rule) plus a short window of host telemetry events around it. The telemetry is from an organisation's own monitored endpoints. Decide whether the alert reflects malicious activity or benign/administrative activity, map it to MITRE ATT&CK, and recommend a response.

Rules:
- Base your verdict on the evidence in the events. The rule's own tags are a hint, not ground truth; rules misfire.
- Consider the parent process, user, command line, integrity level, timing and what surrounds the trigger event.
- Administrative tooling (remote management shells, monitoring agents, provisioning scripts, logons from a management host) is common in this environment and is benign unless the evidence shows otherwise.
- Answer only with a JSON object matching the schema. No prose outside the JSON.
"""

ANSWER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "verdict",
        "confidence",
        "techniques",
        "tactic",
        "severity",
        "reasoning",
        "actions",
    ],
    "properties": {
        "verdict": {"type": "string", "enum": ["malicious", "benign"]},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "techniques": {
            "type": "array",
            "items": {"type": "string", "pattern": "^T\\d{4}(\\.\\d{3})?$"},
            "description": "MITRE ATT&CK technique ids that best describe the activity (empty if benign)",
        },
        "tactic": {
            "type": ["string", "null"],
            "description": "Primary ATT&CK tactic slug, e.g. credential-access, or null if benign",
        },
        "severity": {
            "type": "string",
            "enum": ["informational", "low", "medium", "high", "critical"],
        },
        "reasoning": {"type": "string", "description": "2-4 sentences citing the evidence"},
        "actions": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Recommended response steps, most urgent first",
        },
    },
}


class Answer(BaseModel):
    model_config = ConfigDict(extra="ignore")

    verdict: str
    confidence: float = 0.5
    techniques: list[str] = Field(default_factory=list)
    tactic: str | None = None
    severity: str = "medium"
    reasoning: str = ""
    actions: list[str] = Field(default_factory=list)


def user_prompt(task_payload: dict[str, Any]) -> str:
    return (
        "Triage this alert.\n\n"
        f"```json\n{json.dumps(task_payload, indent=1, default=str)}\n```\n\n"
        "Respond with a single JSON object with keys: verdict (malicious|benign), "
        "confidence (0-1), techniques (list of ATT&CK ids), tactic (slug or null), "
        "severity (informational|low|medium|high|critical), reasoning, actions (list)."
    )


_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)
_TECH = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def parse_answer(text: str) -> Answer | None:
    """Extract the JSON object from a model reply; tolerate code fences and prose."""
    candidates = [text.strip()]
    m = _JSON_BLOCK.search(text)
    if m:
        candidates.append(m.group(0))
    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        try:
            answer = Answer.model_validate(data)
        except ValidationError:
            continue
        answer.verdict = answer.verdict.strip().lower()
        if answer.verdict not in ("malicious", "benign"):
            answer.verdict = "malicious" if "malic" in answer.verdict else "benign"
        answer.techniques = [
            t.strip().upper() for t in answer.techniques if _TECH.match(t.strip().upper())
        ]
        answer.tactic = (
            answer.tactic.strip().lower().replace("_", "-").replace(" ", "-")
            if answer.tactic
            else None
        )
        answer.confidence = max(0.0, min(1.0, float(answer.confidence)))
        return answer
    return None


REFUSAL_MARKERS = (
    "i can't help",
    "i cannot help",
    "i can't assist",
    "i cannot assist",
    "i'm not able to",
    "i am unable to",
    "not able to help with",
    "against my guidelines",
    "i won't",
)


def looks_like_refusal(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in REFUSAL_MARKERS) and "{" not in lowered
