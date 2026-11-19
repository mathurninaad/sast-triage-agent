# Agent run 1: what the first real run showed

Date: 12 Nov 2026. Model: `openai/gpt-oss-120b` on Groq. Prompt: `agent-v1` (step 15).
Target: `examples/demo_app` (14 candidates, scored with `eval/labels/demo_app.json`).

## Scores

| | single-shot v3 | agent run 1 |
| --- | --- | --- |
| Real bugs kept | 6 / 6 | 6 / 6 |
| False alarms removed | 0.875 | 0.625 |
| Precision | 0.857 | 0.667 |
| Errors (kept as needs_review) | 0 | 3 |

Every candidate the agent actually judged was judged correctly (11 of 11),
including FP-01, the one single-shot v3 got wrong: it called
`find_references("get_user_by_id")`, found the caller in `app.py`, and saw
the `int()` conversion. All of the lost precision came from 3 crashes on
traps (FP-02, and FP-03 twice), not from wrong judgements. Without the
crashes, precision would have been 1.0.

## What went wrong, and the fix (step 17)

1. **Unparseable replies.** Groq returned `400 output_parse_failed` three
   times: the model wrote its plan ("We need to see where save_stats is
   called") instead of a well-formed tool call. The exception escaped the
   graph, so the candidate became needs_review with an error.
   Fix: the agent node retries up to 2 times with a short nudge, keeping
   the model's text; if it still fails, the agent stops investigating and
   decides with the evidence gathered so far. The final structured call is
   retried the same way.
2. **Namespaced tool names.** The model called `repo_browser.search_code`
   (a habit of gpt-oss), which wasted a call on "no such tool".
   Fix: the prefix is stripped before lookup.
3. **Wrong argument names, silently ignored.** `read_file(line_start=80,
   line_end=84)` returned lines 1-122, because unknown arguments were
   dropped and defaults used. The model got the wrong evidence without
   knowing it. Fix: known aliases are mapped using the tool's own schema;
   any other unknown argument is an error that shows the real signature.

Each fix has a test that replays the exact failing call or error from this run.
Verdicts now record `parse_retries` and `repaired_calls`, and the triage
command prints how many were recovered.

## Still to measure

Run 2 with `agent-v3` (steps 16 and 17): the expected outcome is the 3 traps
judged instead of crashing, and the adaptive budget report.
