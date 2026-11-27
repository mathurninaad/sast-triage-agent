# Efficient tool use (step 19)

Agent run 2 got every judgement right but used the tools clumsily: 17 calls
with wrong argument names (`max_results`, `path`, `line_start`), the same
search repeated four times, and whole files read instead of the targeted
tools. Each turn resends the whole conversation, so a large early result is
paid for again on every later turn.

## Changes

0. **Measure.** Every model call's token usage is added to the verdict
   (`tokens_in`, `tokens_out`, `model_calls`), in both modes, and `triage`
   prints a token summary.
1. **Names the model already uses.** Parameters are now `path`, `line_start`,
   `line_end`, `max_results` (the names gpt-oss falls back on); the old names
   are accepted as aliases. A `path` filter also takes a folder or `''`.
2. **Descriptions that say when to use each tool**, and agent guidance that
   ranks them: trace_callers first, read_file only for small ranges, never
   repeat a call.
3. **Less output per call.** `read_file` returns at most 60 lines (was 150);
   a repeated call gets a one-line "already run" reply; new `trace_callers`
   returns each caller with its code (find_references plus get_function per
   caller, in one call).

Also: the evidence check accepts a quote that is defined elsewhere and used
by name on the cited line (agent run 2, FP-02), which was a false flag.

## Offline measurement (before run 3)

At about 4 characters per token:

| | before | after |
| --- | --- | --- |
| Tool schemas + guidance, resent every turn | 4,558 chars | 6,144 chars (about +400 tokens per turn) |
| Run 2's typical investigation output | 4,492 chars | 2,421 chars (about -520 tokens, saved on every later turn) |
| Tool turns to answer FP-01 | 2 | 1 |

The trade-off: a candidate decided with no tool calls now costs slightly
more, an investigation costs less. Run 3 measures the net effect.

## When the flagged function starts outside the code window

The opening prompt shows the flagged lines plus 12 lines either side. In a
long function the `def` line, the route decorator and the source of the data
can all be outside that window. Experiment (`sast-experiments/enclosing_header.py`,
a 49-line Flask view with the SQL on line 69 and `def` on line 29, run with
the real model):

| | first call | calls | tokens (mean) |
| --- | --- | --- | --- |
| nothing extra (3 runs) | a guessed name that does not exist, every time (`app.get_sales`, `app.main`) | 3: the guess, then the whole file in two reads | 13,584 |
| function header in the prompt (3 runs) | `get_function('export_report')`, every time | 1 to 4 | 12,775 |

All judgements were correct. About 89% of tokens are input (the conversation
resent each turn), so each turn costs far more than a few prompt lines.

Decision: the model looks for the definition in the window first; only if it
is not there does it call the new `get_enclosing_function` tool, once (name,
line range and header: decorators and signature), and uses that name from
then on. A repeat of the same lookup gets the one-line "already run" reply.
