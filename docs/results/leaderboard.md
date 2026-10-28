# SOC-analyst benchmark leaderboard (2026-10-28)

154 tasks: 116 malicious (EVTX-ATTACK-SAMPLES, labelled), 38 benign (lab admin noise). SigmaHQ windows rules, one fresh context per task, no tools. Method: docs/benchmark.md.

| model | tasks | verdict acc | F1 | benign acc | technique (exact / family) | tactic | refusals | mean latency | mean cost |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| claude-cli:claude-sonnet-5-5 | 154 | 97% | 0.98 | 97% | 97% / 97% | 72% | 0% | 10.5s | $0.0298 |
| codex-cli:codex-default | 154 | 93% | 0.95 | 100% | 87% / 87% | 69% | 0% | 12.7s | n/a |
