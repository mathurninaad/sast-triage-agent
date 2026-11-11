# Ground-truth labels

Answer keys for evaluation targets: for each planted or known issue, the
correct verdict, CWE, file and line range. They live here, outside the
scanned folders, so the triage agent can never read them while it works.

| File | Target |
| --- | --- |
| `demo_app.json` | `examples/demo_app` |

A scanner finding matches a label when it is in the same file and its line
falls inside the label's line range (inclusive). File paths are relative to
the target folder.
