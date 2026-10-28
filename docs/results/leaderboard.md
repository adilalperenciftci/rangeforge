# SOC-analyst benchmark leaderboard (2026-10-28)

154 tasks: 116 malicious (EVTX-ATTACK-SAMPLES, labelled), 38 benign (lab admin noise). SigmaHQ windows rules, one fresh context per task, no tools. Claude models via the Claude Code CLI, Codex via the Codex CLI with its account default model. Method: docs/benchmark.md.

| model | tasks | verdict acc | F1 | benign acc | technique (exact / family) | tactic | refusals | mean latency | mean cost |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| claude-cli:claude-opus-5-5 | 154 | 99% | 0.99 | 100% | 98% / 98% | 72% | 0% | 9.8s | $0.0431 |
| claude-cli:claude-sonnet-5-5 | 154 | 97% | 0.98 | 97% | 97% / 97% | 72% | 0% | 10.5s | $0.0298 |
| codex-cli:codex-default | 154 | 93% | 0.95 | 100% | 87% / 87% | 69% | 0% | 12.7s | n/a |
| claude-cli:claude-haiku-5-5 | 154 | 90% | 0.94 | 74% | 95% / 95% | 69% | 0% | 10.7s | $0.0017 |
