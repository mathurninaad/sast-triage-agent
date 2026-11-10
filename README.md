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

## Scan (all scanners + dedupe)

```bash
uv run sast-triage scan examples/demo_app
uv run sast-triage scan https://github.com/adeyosemanputra/pygoat
```

Runs Semgrep (rules picked from the detected languages) and, for Python
code, Bandit; converts everything into `Finding`s; then merges findings
that point at the same place into **candidates**: same file, and either
overlapping lines or at most 2 lines apart with a shared CWE. Each
candidate keeps all its original findings. On the demo app, 32 findings
become 12 candidates, each matching exactly one labelled item.

Everything for one scan goes into `reports/<name>/`: `candidates.json`,
`findings.json`, the raw `semgrep.json` / `bandit.json`, and `meta.json`.

## Triage with an LLM (single-shot baseline)

After a scan, an LLM judges each candidate: `true_positive`,
`false_positive` or `needs_review`, with reasoning, an exploit scenario and
a fix. It sees the flagged lines with 12 lines of context, every rule that
fired, and CodeQL's data-flow trace when there is one. It **cannot open
other files**; that is the job of the tool-using agent (next milestone), and
this is the baseline that agent must beat.

Models run on [Groq](https://console.groq.com/). Put your key in a `.env`
file in the project folder (it is git-ignored, so it is never committed):

```bash
echo "GROQ_API_KEY=your-key-here" > .env
```

```bash
uv run sast-triage scan examples/demo_app
uv run sast-triage triage reports/demo_app                          # default: openai/gpt-oss-120b
uv run sast-triage triage reports/demo_app --model llama-3.3-70b-versatile
uv run sast-triage evaluate reports/demo_app --labels eval/labels/demo_app.json
```

To compare two runs (for example after changing the prompt or the model),
save them under different names:

```bash
uv run sast-triage triage reports/demo_app --out verdicts-llama.json --model llama-3.3-70b-versatile
uv run sast-triage evaluate reports/demo_app --labels eval/labels/demo_app.json --verdicts verdicts-llama.json
```

Bandit's "risky module imported" warnings (B401-B415) are dismissed by a
fixed rule without calling the LLM: an import is never exploitable on its
own, and each use of the module is flagged separately.

`evaluate` compares the verdicts with the answer key: real bugs kept,
false alarms removed, precision, and end-to-end recall (which also counts
bugs no scanner reported), next to the scanners-only baseline. If an LLM
call fails, that candidate is kept as `needs_review` with the error noted.
Code is passed to the model inside `<code>` tags and marked as untrusted, so
instructions hidden in comments are not followed.

## CodeQL

`scan` runs [CodeQL](https://codeql.github.com/) as a core scanner when it is
installed. It is the only scanner here that tracks data across functions and
files, and each of its findings carries a source-to-sink `trace`. On the demo
app it is the only one that finds the path traversal.

CodeQL is **not bundled**; install it yourself (the bundle includes the queries):

```bash
curl -LO https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-osx64.tar.gz
mkdir -p ~/tools && tar -xzf codeql-bundle-osx64.tar.gz -C ~/tools
export PATH="$HOME/tools/codeql:$PATH"   # or: export SAST_TRIAGE_CODEQL=~/tools/codeql/codeql
codeql version
```

(Use `codeql-bundle-linux64.tar.gz` on Linux.) If CodeQL isn't found, `scan`
says so and continues with the other scanners.

**Licence:** CodeQL's terms allow analysing open-source code, academic research
and demos. Analysing private or commercial code needs a paid GitHub Advanced
Security licence. `scan` prints this reminder on every run; use `--no-codeql`
to skip it.

Only languages CodeQL can analyse **without building the project** are used:
Python, JavaScript/TypeScript, Ruby, Java and C#. Others (C/C++, Go, Kotlin,
Swift) would mean running the project's own build scripts, which this tool
never does, so they are skipped with a message.

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
