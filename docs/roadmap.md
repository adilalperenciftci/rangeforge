# Roadmap

RangeForge grows in layers. Each layer is useful on its own and is measured
before the next one starts.

## 1. Ingest and schema (done)

- OCSF-aligned `NormalizedEvent` with a flat native field view
- Sysmon and Security channel mapping
- EVTX reader on the Rust `evtx` parser
- Linux auditd normalizer (next)

## 2. Detection engine (done)

- Sigma rules compiled straight to Python predicates; the full SigmaHQ Windows
  and Linux rule sets compile with zero failures
- Event-id indexed streaming evaluation
- Multi-stage correlation (sequence / threshold / value-count windows) (next)
- Rule-loading cache to cut cold-start time (next)

## 3. Coverage measurement (done, growing)

- Replay of EVTX-ATTACK-SAMPLES with technique labels from file names
- Technique / tactic coverage, noisy-rule ranking, missed-sample list
- ATT&CK Navigator layer export
- Curated label overrides for samples that carry no technique id (next)
- OTRF Security-Datasets as a second source (next)

## 4. Live lab telemetry

- Collector for Windows (Sysmon + Security via WinRM/WEF) and Ubuntu (auditd)
- Lab provisioning: Hyper-V checkpoints, Sysmon with a tuned config, audit
  policy baseline, auditd rule set
- Continuous evaluation of lab hosts against the rule set

## 5. SOC-analyst benchmark

- Alert triage tasks built from replayed, labelled alerts (true positives,
  benign noise, ambiguous cases)
- Model-agnostic backends: Claude Code CLI, Codex CLI, Ollama, Anthropic and
  OpenAI APIs
- Scoring: verdict accuracy, ATT&CK mapping accuracy, response quality, cost,
  latency; refusal-rate tracking
- Published leaderboard and methodology write-up

## 6. Hardening as code

- CIS-style checks for the lab hosts with drift detection over time
