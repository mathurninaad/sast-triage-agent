"""Merge findings from all scanners into candidates: one per suspicious location.

Several rules, often from different scanners, routinely flag the same spot
(on the demo app, 32 findings point at 12 places). Triage should judge each
place once, so findings are grouped:

  same file, and
  - their line ranges overlap, or
  - they are at most `max_gap` lines apart and share a CWE.

The second case covers a bug spread over adjacent lines, such as Bandit
flagging the line that builds a SQL query (15) and Semgrep the line that
runs it (16). Requiring a shared CWE there keeps unrelated neighbours apart.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from sast_triage.models import Candidate, Finding, max_severity
from sast_triage.scanners.semgrep import read_snippet

DEFAULT_MAX_GAP = 2


class _Group:
    def __init__(self, first: Finding):
        self.findings = [first]
        self.start = first.location.start_line
        self.end = first.location.end_line
        self.cwes = set(first.cwe)

    def accepts(self, f: Finding, max_gap: int) -> bool:
        loc = f.location
        if loc.start_line <= self.end:  # overlapping (findings arrive sorted by start)
            return True
        near = loc.start_line - self.end <= max_gap
        return near and bool(self.cwes & set(f.cwe))

    def add(self, f: Finding) -> None:
        self.findings.append(f)
        self.end = max(self.end, f.location.end_line)
        self.cwes |= set(f.cwe)


def _candidate_id(findings: list[Finding]) -> str:
    joined = "|".join(sorted(f.fingerprint for f in findings))
    return hashlib.sha256(joined.encode()).hexdigest()[:16]


def group_findings(
    findings: list[Finding], base_dir: Path, max_gap: int = DEFAULT_MAX_GAP
) -> list[Candidate]:
    """Group findings into candidates, sorted by file and line."""
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.location.file, []).append(f)

    candidates: list[Candidate] = []
    for file in sorted(by_file):
        ordered = sorted(by_file[file], key=lambda f: (f.location.start_line, f.location.end_line))
        groups: list[_Group] = []
        for f in ordered:
            if groups and groups[-1].accepts(f, max_gap):
                groups[-1].add(f)
            else:
                groups.append(_Group(f))
        for g in groups:
            candidates.append(
                Candidate(
                    id=_candidate_id(g.findings),
                    file=file,
                    start_line=g.start,
                    end_line=g.end,
                    snippet=read_snippet(base_dir, file, g.start, g.end),
                    cwe=sorted(g.cwes),
                    severity=max_severity([f.severity for f in g.findings]),
                    scanners=sorted({f.scanner for f in g.findings}),
                    findings=g.findings,
                )
            )
    return candidates
