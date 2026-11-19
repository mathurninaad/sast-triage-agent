# Evidence check on the saved demo-app verdicts

Step 18 checks the code each verdict cites (see `src/sast_triage/evidence.py`).
Before relying on it, it was run on the two existing real runs, to see how it
behaves on genuine model output and whether it wrongly flags correct dismissals.

- `verdicts.json`: single-shot, prompt v3. Checked against the code window the
  model was shown.
- `verdicts-agent.json`: agent run 1. The transcripts were not saved, so this
  checked files, lines and quotes, but not whether the agent had read them.

## What real citations look like

Almost never `file:line`. Instead: `line 58`, `lines 59‑61` (with a Unicode
hyphen), `app.py (line 34)`, `on lines 23‑24 of db.py`, and code in backticks.
The first version of the extractor got two things wrong on this output, and
both were fixed:

1. It split sentences on the dot in `pickle.loads`, losing citations.
2. It gave a bare "line 15" to the last file named anywhere earlier (app.py),
   when it meant the flagged file (db.py). Now a bare line number belongs to a
   file named in the same sentence, or else to the flagged file.

## Results

| | single-shot v3 | agent run 1 |
| --- | --- | --- |
| Correct false positives wrongly sent to review | 0 | 0 |
| Verdicts with all citations verified | 12 of 12 checked | 8 of 9 checked |
| Contradicted citations | 0 | 1 (on a true positive) |

The one contradiction is real. On TP-01 the agent wrote "`db.find_users_by_name(name)`
(db.py line 13)", but that call is in app.py, not at db.py line 13. The verdict
is a true positive, so the one-sided rule leaves it alone, but the sloppy
citation now shows in the report.

So on these runs the check costs nothing: every correct dismissal cited real
code it had been shown. Its value is for the cases these runs did not hit, where
the model cites a line that does not exist, quotes code that is not there, or
cites code it never read. The tests in `tests/test_evidence.py` cover each case.

(Checked means judged by the model: the import-warning rule and the 3 crashed
candidates of run 1 have nothing to check.)
