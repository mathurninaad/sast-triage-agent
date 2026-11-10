# Experiment: adding CodeQL as a scanner

**Question:** does CodeQL find what Semgrep CE and Bandit miss, enough to be
worth its setup? **Decision:** yes, adopted as a core scanner (step 9).

Setup: CodeQL 2.27.4, `python-security-extended` suite, build mode `none`.
Semgrep 1.183.0 with all `python/` rules from semgrep-rules at `16b9e6d`,
Bandit 1.9.4. Demo app labels at the time: 6 real bugs, 5 traps (FP-06 was
added afterwards, see below).

## Demo app, each scanner alone

| Scanner | Real bugs found | Traps flagged | Locations |
| --- | --- | --- | --- |
| Semgrep | 5 of 6 (misses TP-04) | 4 of 4 | 12 |
| Bandit | 4 of 6 (misses TP-02, TP-04) | 5 of 5 | 10 |
| CodeQL | **6 of 6** | 1 of 4 (FP-02), plus 1 new false alarm | 8 |

Semgrep-only and CodeQL-only runs count traps out of 4, because FP-05
exists only in Bandit's output.

By item, CodeQL: 6 real, 2 false alarms (precision 0.75, recall 1.0).
Semgrep: 5 real, 4 false (precision 0.56, recall 0.83).

- **TP-04 path traversal:** found only by CodeQL (`py/path-injection`).
- **TP-01 cross-file SQL injection:** CodeQL reports the full flow, from
  `request.args.get("name")` in app.py through the call into db.py to
  `conn.execute(query)`. Semgrep CE only matched the query's shape.
- **Traps CodeQL correctly ignored:** FP-01 (it saw the `int()` in the other
  file), FP-03 (no user input reaches the pickle file), FP-04 (ETag MD5 is
  not sensitive data). It still flagged FP-02 (validated, quoted `ping`).
- **New false alarm:** `py/reflective-xss` at app.py:89 on a route that
  returns a dict (Flask sends JSON). Added to the labels as FP-06.

## All three merged (`sast-triage scan`)

41 findings (22 Semgrep, 10 Bandit, 9 CodeQL) -> 14 candidates covering
all 6 real bugs and all 6 traps. The scan took about 2.5 minutes, most of
it Semgrep.

## PyGoat (practicality)

Database 8 s, queries 27 s; 62 results at 58 locations, 39 with code flows
(Semgrep: 148 security results; Bandit: 130).

## Caveats

- The demo app's bugs are textbook cases CodeQL's queries target; a labelled
  PyGoat is the fairer test.
- Licence: open-source code, research and demos only, unless the user has a
  paid GitHub Advanced Security licence.
- Compiled languages need a build (running the repo's scripts), so they are
  not supported.
