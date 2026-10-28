# RangeForge

**Detection engineering lab and LLM SOC-analyst benchmark, built on real host telemetry.**

RangeForge turns a small Hyper-V lab (Windows + Ubuntu + Kali) into a reproducible
detection-engineering workbench:

- **Ingest** Windows Sysmon / Security logs and Linux auditd into a single
  [OCSF](https://schema.ocsf.io)-aligned event model.
- **Detect** with Sigma rules compiled to a native streaming engine, plus
  multi-stage correlation across hosts and time windows.
- **Measure** detection coverage by replaying public, ATT&CK-labelled telemetry
  datasets and rendering an ATT&CK Navigator heat-map.
- **Benchmark** how well LLMs perform as SOC analysts: alert triage, ATT&CK
  mapping and response recommendations, scored against ground truth across
  Claude, OpenAI and local models.
- **Harden** lab hosts with CIS-style checks and drift detection.

RangeForge is strictly defensive. It does not generate attacks; it evaluates how
well humans and machines *detect* them.

## Status

Early development. See [docs/roadmap.md](docs/roadmap.md).

## Quick start

```bash
python -m venv .venv && .venv/Scripts/activate   # or source .venv/bin/activate
pip install -e ".[dev]"
rf --help
```

## License

Apache-2.0
