"""Run Bandit (a Python-only security linter) and convert its output into Findings.

Bandit checks each Python file against a fixed list of risky calls and
patterns (B101, B602, ...). It overlaps a lot with Semgrep but catches a
few things Semgrep's rules don't, such as the "risky module imported"
warnings, so running both raises recall.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from sast_triage.detect import SKIP_DIRS
from sast_triage.models import Finding, Location, Severity, fingerprint
from sast_triage.scanners.semgrep import read_snippet

_SEVERITY = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH}


class BanditError(RuntimeError):
    """Bandit could not be run or did not produce usable output."""


def bandit_executable() -> str:
    """Find the bandit binary, preferring the one in our own environment."""
    local = Path(sys.executable).with_name("bandit")
    if local.exists():
        return str(local)
    found = shutil.which("bandit")
    if found is None:
        raise BanditError("bandit is not installed; run `uv sync`")
    return found


def build_command(target: str) -> list[str]:
    """-r: recurse into folders; -f json: machine-readable; -q: no progress banner.
    -x: skip the same dependency and tool folders language detection skips."""
    exclude = ",".join(f"*/{d}/*" for d in sorted(SKIP_DIRS))
    return [bandit_executable(), "-r", target, "-f", "json", "-q", "-x", exclude]


def run_bandit(target: Path, timeout: int = 1800) -> dict[str, Any]:
    """Run bandit on `target` and return its parsed JSON output, unchanged.

    Like run_semgrep, it runs from inside the target folder so paths come
    back relative to it. Bandit exits with 1 whenever it finds issues, so
    success is judged by getting valid JSON, not by the exit code.
    """
    if not target.exists():
        raise BanditError(f"target does not exist: {target}")
    target = target.resolve()
    cwd, scan_arg = (target, ".") if target.is_dir() else (target.parent, target.name)
    proc = subprocess.run(
        build_command(scan_arg), capture_output=True, text=True, timeout=timeout, cwd=cwd
    )
    try:
        output = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise BanditError(
            f"bandit exited with code {proc.returncode} and no JSON output:\n"
            f"{proc.stderr.strip()[-2000:]}"
        ) from None
    if "results" not in output:
        raise BanditError(f"unexpected bandit output, keys: {sorted(output)}")
    return output


def _rel_path(filename: str) -> str:
    """'./app.py' -> 'app.py'."""
    return filename[2:] if filename.startswith("./") else filename


def _cwe(result: dict[str, Any]) -> list[str]:
    cwe = result.get("issue_cwe") or {}
    return [f"CWE-{cwe['id']}"] if cwe.get("id") else []


def summarize(output: dict[str, Any]) -> dict[str, Any]:
    """Counts by rule, file, severity, confidence and CWE (same shape as Semgrep's)."""
    results = output.get("results", [])
    by = {key: Counter() for key in ("severity", "confidence", "cwe", "rule", "file")}
    for r in results:
        by["rule"][f"{r['test_id']} {r['test_name']}"] += 1
        by["file"][_rel_path(r["filename"])] += 1
        by["severity"][r.get("issue_severity", "unknown")] += 1
        by["confidence"][r.get("issue_confidence", "unknown")] += 1
        for cwe in _cwe(r) or ["none"]:
            by["cwe"][cwe] += 1
    locations = {(r["filename"], r["line_number"]) for r in results}
    return {
        "version": None,
        "results": len(results),
        "unique_locations": len(locations),
        "files_scanned": len([k for k in output.get("metrics", {}) if k != "_totals"]),
        "errors": len(output.get("errors", [])),
        "skipped_rules": 0,
        "by": {key: dict(counter.most_common()) for key, counter in by.items()},
    }


def to_findings(output: dict[str, Any], base_dir: Path) -> list[Finding]:
    """Convert Bandit's raw output into Findings."""
    findings: list[Finding] = []
    seen: dict[str, int] = {}
    for r in output.get("results", []):
        path = _rel_path(r["filename"])
        lines = r.get("line_range") or [r["line_number"]]
        start, end = min(lines), max(lines)
        snippet = read_snippet(base_dir, path, start, end)
        rule_id = f"{r['test_id']}.{r['test_name']}"  # e.g. "B602.subprocess_popen_with_shell_equals_true"

        fp = fingerprint("bandit", rule_id, path, snippet)
        seen[fp] = seen.get(fp, 0) + 1
        if seen[fp] > 1:
            fp = f"{fp}-{seen[fp]}"

        col = r.get("col_offset")
        end_col = r.get("end_col_offset")
        findings.append(
            Finding(
                fingerprint=fp,
                scanner="bandit",
                rule_id=rule_id,
                message=r.get("issue_text", ""),
                severity=_SEVERITY.get(str(r.get("issue_severity", "")).upper(), Severity.MEDIUM),
                cwe=_cwe(r),
                location=Location(
                    file=path,
                    start_line=start,
                    end_line=end,
                    # Bandit counts columns from 0, our model (like Semgrep) from 1.
                    start_col=col + 1 if col is not None else None,
                    end_col=end_col + 1 if end_col is not None else None,
                ),
                snippet=snippet,
                category="security",  # every Bandit check is a security check
                confidence=r.get("issue_confidence"),
                references=[r["more_info"]] if r.get("more_info") else [],
            )
        )
    return findings
