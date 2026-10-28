# SOC-analyst benchmark: methodology

## Question

Given one alert from a production-grade rule set and a short window of the
telemetry around it, can a model decide correctly whether it is malicious,
name the ATT&CK technique, and propose a sensible response?

## Task construction

Tasks are produced by `rf bench build` from two populations.

**Malicious.** EVTX-ATTACK-SAMPLES captures are replayed through the SigmaHQ
Windows rule set. Every alert whose rule is tagged with the capture's labelled
technique (or that technique's parent / sub-technique) becomes a candidate.
Candidates are de-duplicated per rule and capped at three per capture so a
single noisy capture cannot dominate.

**Benign.** Telemetry collected from the lab hosts while only administrative
activity was taking place (the collector's own WinRM sessions, provisioning
scripts, hypervisor-side logons) is replayed through the same rules. Every alert
is, by construction, a false positive, and becomes a benign task, capped at
three per rule.

Alerts that fired inside an attack capture but do not match its technique are
excluded: they may be noise or an unlabelled side effect, and we do not guess.

Each task carries the alert (rule title, level, the rule's own ATT&CK tags,
key fields, a one-line summary) and up to eight preceding and four following
events with a fixed, trimmed field set. The model never sees the ground truth,
the dataset file name, or the technique label.

## Prompt

One system prompt for every backend (see `rangeforge/bench/prompt.py`). It
frames the model as a SOC analyst, states that rule tags are hints rather than
truth, notes that administrative tooling is common in the environment, and
requires a single JSON object. Backends that support structured output receive
the JSON schema; the parser tolerates fences and prose for those that do not.

## Scoring

| metric | definition |
|---|---|
| verdict accuracy | (TP + TN) / answered |
| precision / recall / F1 | on the *malicious* class |
| benign accuracy | TN / (TN + FP): how often admin noise is correctly dismissed |
| technique, exact | malicious tasks where a predicted technique id equals a label |
| technique, family | ... or is the label's parent or one of its sub-techniques |
| tactic | predicted tactic slug equals the capture's tactic |
| refusal rate | replies with no JSON that read as a refusal, over all tasks |
| calibration gap | mean confidence on correct verdicts minus mean confidence on wrong ones |
| latency, cost | per task; cost only where the backend reports it |

Unparseable replies count as errors, not as wrong verdicts, and are retried on
the next run.

## Backends

`claude-cli` and `codex-cli` use the operator's existing subscriptions through
the vendors' CLIs, so the benchmark can run without API keys. `anthropic`,
`openai` and `ollama` call the HTTP APIs directly. All backends are stateless:
one fresh context per task, no tools.

## Threats to validity

- **Label granularity.** The v1 task set (the one on the leaderboard) was built
  when technique labels still came from capture file names and a keyword
  table: 142 captures were labelled and 128 were excluded from the malicious
  population. Those 128 have since been hand-labelled
  (`datasets/labels/evtx-attack-samples.yaml`); a v2 task set built from all
  270 captures will be reported separately so the two are never mixed.
- **Context window.** Twelve events is enough for most process-tree decisions
  and not enough for slow, multi-host campaigns. This benchmark measures
  single-alert triage, not investigation.
- **Benign population size.** Lab admin noise is real but narrow (one Windows
  host, one Linux host, a handful of tools). A model that learns "WinRM is
  fine" is right here and may be wrong elsewhere.
- **Rule-tag leakage.** The alert includes the rule's ATT&CK tags. For
  malicious tasks these overlap the ground truth by construction, which makes
  the technique metric partly a test of *trusting the rule*. The benign tasks
  are where that trust is punished.
- **Model drift.** CLI backends resolve to whatever model the vendor serves
  under a name on the day of the run; the response file records the name and
  timestamp.
