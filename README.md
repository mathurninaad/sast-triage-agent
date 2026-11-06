# SAST Triage Agent

Runs SAST scanners (Semgrep, Bandit) on a codebase, then hands each finding to an
AI agent that investigates it like a security engineer would and decides whether
it is a real vulnerability.

> Work in progress. Built step by step; see the project plan for the roadmap.

## Setup

```bash
uv sync
uv run sast-triage version
```

## Semgrep baseline

```bash
# show which languages are detected and which rule folders they map to
uv run sast-triage languages examples/demo_app

# scan with rules picked automatically from the detected languages
uv run sast-triage semgrep examples/demo_app

# or choose the rules yourself
uv run sast-triage semgrep examples/demo_app -c p/python -c p/flask
```

When no `-c` is given, Semgrep's open-source rules
([semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules)) are
downloaded once, pinned to a commit, into `~/.cache/sast-triage/` (override
with `SAST_TRIAGE_CACHE`). They are licensed under the Semgrep Rules License
v1.0, which does not allow redistributing them, so they are never copied into
this repository. The summary counts only security results; the raw JSON in
`reports/` is Semgrep's full output.

## Run tests

```bash
uv run pytest
```
