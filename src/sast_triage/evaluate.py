"""Score triage verdicts against a ground-truth label file.

Each candidate is matched to the label whose line range it overlaps in the
same file. A candidate counts as "kept" (shown to the user) when triage says
true_positive or needs_review, and "dismissed" when it says false_positive.

Metrics, each computed for the triage result and for the no-triage baseline
(where every candidate is kept):

- real_kept / real_candidates: real bugs that reached triage and survived it
- recall_end_to_end: real bugs kept / all real bugs in the labels, which also
  counts bugs no scanner reported
- false_alarms_removed: false-positive candidates dismissed / all of them
- precision: real candidates kept / all candidates kept
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sast_triage.models import Candidate
from sast_triage.triage import Verdict

KEEP = {"true_positive", "needs_review"}


@dataclass
class Row:
    candidate: Candidate
    label: dict[str, Any] | None
    verdict: Verdict | None

    @property
    def truth(self) -> str:
        return self.label["verdict"] if self.label else "unlabelled"

    @property
    def kept(self) -> bool:
        return self.verdict is None or self.verdict.verdict in KEEP

    @property
    def correct(self) -> bool | None:
        if self.label is None or self.verdict is None or self.verdict.verdict == "needs_review":
            return None
        return self.verdict.verdict == self.truth


def load_labels(path: Path) -> list[dict[str, Any]]:
    return json.loads(path.read_text())["labels"]


def match_label(candidate: Candidate, labels: list[dict[str, Any]]) -> dict[str, Any] | None:
    for label in labels:
        lo, hi = label["lines"]
        if label["file"] == candidate.file and candidate.start_line <= hi and candidate.end_line >= lo:
            return label
    return None


def _ratio(n: int, d: int) -> float | None:
    return round(n / d, 3) if d else None


def _metrics(rows: list[Row], labels: list[dict[str, Any]], keep_all: bool) -> dict[str, Any]:
    kept = [r for r in rows if keep_all or r.kept]
    real_rows = [r for r in rows if r.truth == "true_positive"]
    fp_rows = [r for r in rows if r.truth == "false_positive"]
    real_kept = [r for r in real_rows if keep_all or r.kept]
    real_labels = [lab for lab in labels if lab["verdict"] == "true_positive"]
    real_kept_labels = {r.label["id"] for r in real_kept if r.label}
    return {
        "candidates_kept": len(kept),
        "real_kept": len(real_kept),
        "real_candidates": len(real_rows),
        "recall_end_to_end": _ratio(len(real_kept_labels), len(real_labels)),
        "false_alarms_removed": _ratio(len(fp_rows) - len([r for r in fp_rows if keep_all or r.kept]), len(fp_rows)),
        "precision": _ratio(len(real_kept), len([r for r in kept if r.label])),
    }


def evaluate(
    candidates: list[Candidate], verdicts: list[Verdict], labels: list[dict[str, Any]]
) -> dict[str, Any]:
    by_id = {v.candidate_id: v for v in verdicts}
    rows = [Row(c, match_label(c, labels), by_id.get(c.id)) for c in candidates]
    covered = {r.label["id"] for r in rows if r.label}
    return {
        "rows": rows,
        "baseline": _metrics(rows, labels, keep_all=True),
        "triage": _metrics(rows, labels, keep_all=False),
        # Only real bugs count as missed; a false positive no scanner reports is good.
        "missed_by_scanners": [
            lab["id"] for lab in labels
            if lab["verdict"] == "true_positive" and lab["id"] not in covered
        ],
        "needs_review": sum(1 for r in rows if r.verdict and r.verdict.verdict == "needs_review"),
        "errors": sum(1 for r in rows if r.verdict and r.verdict.error),
        "unlabelled": sum(1 for r in rows if r.label is None),
    }
