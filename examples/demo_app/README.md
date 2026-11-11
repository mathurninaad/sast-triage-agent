# Demo app (deliberately vulnerable)

A small Flask app with planted security bugs, used to test and evaluate
sast-triage. **Do not deploy it or expose it to a network.**

It contains two kinds of planted code:

- **Real vulnerabilities** that the triage agent should confirm.
- **False-positive traps**: code that looks dangerous to a scanner but is
  actually safe, which the agent should dismiss.

The correct answer for each one is in `eval/labels/demo_app.json`, kept
outside this folder on purpose: the triage agent can read any file in the
folder it scans, so the answer key must not be in it. The source files
deliberately contain no hints either, so the agent has to work it out from
the code.
