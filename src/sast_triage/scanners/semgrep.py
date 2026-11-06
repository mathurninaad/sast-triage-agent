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


def is_security(result: dict[str, Any]) -> bool:
    """True if the rule that produced this result is a security rule.

    The rules repo also has correctness, maintainability and best-practice
    rules (code quality, not vulnerabilities); those are filtered out.
    """
    return result.get("extra", {}).get("metadata", {}).get("category") == "security"


def security_only(output: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Copy of `output` keeping only security results, plus how many were dropped."""
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
