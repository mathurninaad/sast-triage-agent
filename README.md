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

Any public GitHub repo can be scanned by URL. It is downloaded (latest
commit only, no history) into `~/.cache/sast-triage/repos/` and the exact
commit is recorded:

```bash
uv run sast-triage semgrep https://github.com/adeyosemanputra/pygoat
uv run sast-triage semgrep https://github.com/owner/repo --ref v2.0   # a branch, tag or commit
```

Each scan saves three files in `reports/`:

- `semgrep-<name>.json`: Semgrep's raw output, untouched.
- `semgrep-<name>.meta.json`: the target, commit, rules and versions used.
- `findings-<name>.json`: our own `Finding` format (see `models.py`): clean
  rule IDs, the flagged code snippet, severity, CWEs, the rule's hints, and
  a fingerprint that stays the same when the code moves to other lines.

When no `-c` is given, Semgrep's open-source rules
([semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules)) are
downloaded once, pinned to a commit, into `~/.cache/sast-triage/` (override
with `SAST_TRIAGE_CACHE`). They are licensed under the Semgrep Rules License
v1.0, which does not allow redistributing them, so they are never copied into
this repository. The summary leaves out code-quality results (correctness, maintainability, best-practice); the raw JSON in
`reports/` is Semgrep's full output.

## Bandit baseline

[Bandit](https://bandit.readthedocs.io/) is a Python-only security linter.
It overlaps with Semgrep but catches some things Semgrep's rules don't.

```bash
uv run sast-triage bandit examples/demo_app
uv run sast-triage bandit https://github.com/adeyosemanputra/pygoat
```

It writes `reports/bandit-<name>.json` (raw), a `.meta.json`, and
`reports/findings-bandit-<name>.json` in the same `Finding` format as Semgrep.

## Download cache

Downloaded rules and repos are kept between runs (nothing removes them
automatically) so they aren't downloaded again:

```bash
uv run sast-triage cache info                 # what's cached, commits, sizes
uv run sast-triage cache clear                # delete everything (asks first)
uv run sast-triage cache clear --repos-only   # keep the rules, drop fetched repos
```

`clear` only ever deletes the folders this tool creates, so pointing
`SAST_TRIAGE_CACHE` at a folder with other files in it can't lose them.

## Run tests

```bash
uv run pytest
```
