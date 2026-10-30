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

## Run tests

```bash
uv run pytest
```
