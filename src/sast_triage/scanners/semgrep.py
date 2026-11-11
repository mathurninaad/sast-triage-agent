"""Run Semgrep and summarise its raw JSON output.

This is the baseline: Semgrep's own output, saved untouched and summarised
so we can study it. Converting results into our own Finding model comes in
a later step.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from sast_triage.models import Finding, Location, Severity, fingerprint

_CWE_RE = re.compile(r"CWE-\d+")


class SemgrepError(RuntimeError):
    """Semgrep could not be run or did not produce usable output."""


def semgrep_executable() -> str:
    """Find the semgrep binary, preferring the one in our own environment."""
    local = Path(sys.executable).with_name("semgrep")
    if local.exists():
        return str(local)
    found = shutil.which("semgrep")
    if found is None:
        raise SemgrepError("semgrep is not installed; run `uv sync`")
    return found


def build_command(target: str, configs: list[str] | tuple[str, ...]) -> list[str]:
    """Build the semgrep command line.

    --metrics=off: don't send usage data to Semgrep.
    No --dataflow-traces: the free Community Edition leaves traces out of the
    JSON anyway, so the flag would add nothing.
    """
    if not configs:
        raise ValueError("at least one --config is required")
    cmd = [semgrep_executable(), "scan", "--json", "--metrics=off", "--quiet"]
    for config in configs:
        cmd += ["--config", config]
    cmd.append(target)
    return cmd


def run_semgrep(
    target: Path,
    configs: list[str] | tuple[str, ...],
    timeout: int = 1800,
) -> dict[str, Any]:
    """Run semgrep on `target` and return its parsed JSON output, unchanged.

    Semgrep reports each result's `path` exactly as the target was given, so an
    absolute target gives absolute paths. We always run from inside the target
    folder and scan ".", so paths come back relative to the repo root.
    """
    if not target.exists():
        raise SemgrepError(f"target does not exist: {target}")
    target = target.resolve()
    cwd, scan_arg = (target, ".") if target.is_dir() else (target.parent, target.name)
    # Local rule files must be absolute, since we change the working directory.
    configs = [str(Path(c).resolve()) if Path(c).exists() else c for c in configs]
    proc = subprocess.run(
        build_command(scan_arg, configs),
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
    )
    try:
        output = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise SemgrepError(
            f"semgrep exited with code {proc.returncode} and no JSON output:\n"
            f"{proc.stderr.strip()[-2000:]}"
        ) from None
    if "results" not in output:
        raise SemgrepError(f"unexpected semgrep output, keys: {sorted(output)}")
    return output


# Helpers for reading individual results


# Rule categories that are about code quality, not vulnerabilities.
NON_SECURITY_CATEGORIES = frozenset(
    {"correctness", "maintainability", "best-practice", "performance", "portability", "compatibility"}
)


def is_security(result: dict[str, Any]) -> bool:
    """False only if the rule says it's about code quality, not security.

    Rules without a category (common in custom rules) are kept: hiding a
    possible vulnerability is worse than showing one extra result.
    """
    category = result.get("extra", {}).get("metadata", {}).get("category")
    return category not in NON_SECURITY_CATEGORIES


def security_only(output: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Copy of `output` without code-quality results, plus how many were dropped."""
    results = output.get("results", [])
    kept = [r for r in results if is_security(r)]
    return {**output, "results": kept}, len(results) - len(kept)


def short_rule_id(check_id: str) -> str:
    """'python.lang.security.audit.formatted-sql-query' -> 'formatted-sql-query'."""
    return check_id.rsplit(".", 1)[-1]


def cwe_ids(result: dict[str, Any]) -> list[str]:
    """Pull bare CWE ids ('CWE-89') out of the rule's metadata."""
    cwes = result.get("extra", {}).get("metadata", {}).get("cwe", [])
    if isinstance(cwes, str):
        cwes = [cwes]
    return [m.group(0) for c in cwes if (m := _CWE_RE.search(c))]


def _first(value: Any, default: str = "unknown") -> str:
    """Metadata fields are sometimes a list, sometimes a string."""
    if isinstance(value, list):
        return str(value[0]) if value else default
    return str(value) if value else default


def summarize(output: dict[str, Any]) -> dict[str, Any]:
    """Count results along the dimensions we care about for triage."""
    results = output.get("results", [])
    by = {key: Counter() for key in ("rule", "file", "severity", "subcategory", "confidence", "cwe")}
    for r in results:
        meta = r.get("extra", {}).get("metadata", {})
        by["rule"][short_rule_id(r["check_id"])] += 1
        by["file"][r["path"]] += 1
        by["severity"][r.get("extra", {}).get("severity", "unknown")] += 1
        by["subcategory"][_first(meta.get("subcategory"))] += 1
        by["confidence"][_first(meta.get("confidence"))] += 1
        for cwe in cwe_ids(r) or ["none"]:
            by["cwe"][cwe] += 1
    locations = {(r["path"], r["start"]["line"]) for r in results}
    return {
        "version": output.get("version"),
        "results": len(results),
        "unique_locations": len(locations),
        "files_scanned": len(output.get("paths", {}).get("scanned", [])),
        "errors": len(output.get("errors", [])),
        "skipped_rules": len(output.get("skipped_rules", [])),
        "by": {key: dict(counter.most_common()) for key, counter in by.items()},
    }


# Converting raw results into our Finding model

_SEVERITY = {
    "INFO": Severity.LOW,
    "LOW": Severity.LOW,
    "WARNING": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "ERROR": Severity.HIGH,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    return [str(v) for v in value] if isinstance(value, list) else [str(value)]


def _path_prefix(path: Path) -> str:
    """How Semgrep turns a rules folder into a rule-ID prefix.

    /Users/me/.cache/x  ->  'Users.me..cache.x.'
    """
    return str(path.resolve()).lstrip("/").replace("/", ".") + "."


def clean_rule_id(check_id: str, configs: list[str] | tuple[str, ...]) -> str:
    """Strip the machine-specific folder prefix Semgrep adds for local rules.

    For rules loaded from a folder, Semgrep puts that folder's full path in
    front of the rule ID, so the same rule would get a different ID on every
    machine. Registry rules (p/python) have no prefix and are left alone.
    """
    for config in configs:
        path = Path(config)
        if not path.exists():
            continue  # a registry name, not a local path
        # Semgrep prefixes the full dotted path of each rule file's folder.
        # Cutting at the config's parent keeps the meaningful part: for the
        # rules folder <cache>/python that leaves "python.lang.security...",
        # the same ID the registry uses.
        prefix = _path_prefix(path.parent)
        if check_id.startswith(prefix):
            return check_id[len(prefix):]
    return check_id


def read_snippet(base_dir: Path, rel_path: str, start: int, end: int) -> str:
    """Lines start..end (1-based, inclusive) of a scanned file, or '' if unreadable."""
    try:
        lines = (base_dir / rel_path).read_text(errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[start - 1 : end])


def to_findings(
    output: dict[str, Any],
    base_dir: Path,
    configs: list[str] | tuple[str, ...],
) -> list[Finding]:
    """Convert Semgrep's raw output into Findings.

    `base_dir` is the folder Semgrep ran in (result paths are relative to
    it), used to read each snippet. `configs` are the --config values used,
    needed to clean up rule IDs.
    """
    findings: list[Finding] = []
    seen: dict[str, int] = {}
    for r in output.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        rule_id = clean_rule_id(r["check_id"], configs)
        start, end = r["start"]["line"], r["end"]["line"]
        snippet = read_snippet(base_dir, r["path"], start, end)

        fp = fingerprint("semgrep", rule_id, r["path"], snippet)
        # The same rule on two identical lines in one file: keep both, distinctly.
        seen[fp] = seen.get(fp, 0) + 1
        if seen[fp] > 1:
            fp = f"{fp}-{seen[fp]}"

        findings.append(
            Finding(
                fingerprint=fp,
                scanner="semgrep",
                rule_id=rule_id,
                message=" ".join(str(extra.get("message", "")).split()),
                severity=_SEVERITY.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM),
                cwe=cwe_ids(r),
                location=Location(
                    file=r["path"],
                    start_line=start,
                    end_line=end,
                    start_col=r["start"].get("col"),
                    end_col=r["end"].get("col"),
                ),
                snippet=snippet,
                category=meta.get("category"),
                subcategory=_first(meta.get("subcategory"), default="") or None,
                confidence=_first(meta.get("confidence"), default="") or None,
                likelihood=_first(meta.get("likelihood"), default="") or None,
                impact=_first(meta.get("impact"), default="") or None,
                owasp=_as_list(meta.get("owasp")),
                references=_as_list(meta.get("references")),
            )
        )
    return findings
