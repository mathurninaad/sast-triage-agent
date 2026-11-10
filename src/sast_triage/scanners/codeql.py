"""Run GitHub CodeQL and convert its SARIF output into Findings.

Unlike Semgrep's free edition, CodeQL tracks data across functions and
files, so it can follow user input from a route in one file to a database
call in another, and it reports that path (a "code flow"). We keep it as a
`trace` on each Finding.

CodeQL is not bundled with this tool: users install it themselves, and its
licence (github.com/github/codeql-cli-binaries) allows open-source code,
academic research and demos, while private or commercial code needs a paid
GitHub Advanced Security licence. Hence the notice printed on every run.

Only languages CodeQL can analyse without building the project are
supported. Building means running the project's own build scripts, i.e.
executing code from a possibly untrusted repo, which we never do.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from sast_triage.detect import SKIP_DIRS
from sast_triage.models import Finding, Location, Severity, TraceStep, fingerprint
from sast_triage.scanners.semgrep import read_snippet

LICENSE_NOTICE = (
    "CodeQL's licence allows open-source code, academic research and demos; "
    "analysing private or commercial code needs a paid GitHub Advanced Security "
    "licence. Use --no-codeql to skip it."
)

# Our language names (detect.py) -> CodeQL's, for languages it analyses without a build.
NO_BUILD_LANGUAGES: dict[str, str] = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "javascript",  # CodeQL's javascript extractor covers TypeScript
    "ruby": "ruby",
    "java": "java",
    "csharp": "csharp",
}
# Languages CodeQL supports only by building the project (not supported here).
NEEDS_BUILD = frozenset({"c", "go", "kotlin", "swift", "rust"})

_CWE_TAG = re.compile(r"external/cwe/cwe-0*(\d+)$")
_MD_LINK = re.compile(r"\[([^\]]+)\]\(\d+\)")  # "[user-provided value](1)" -> "user-provided value"


class CodeQLError(RuntimeError):
    """CodeQL could not be run or did not produce usable output."""


def codeql_executable() -> str | None:
    """Path to the codeql binary: $SAST_TRIAGE_CODEQL, else `codeql` on PATH."""
    if custom := os.environ.get("SAST_TRIAGE_CODEQL"):
        return custom if Path(custom).exists() else None
    return shutil.which("codeql")


def plan_languages(detected: list[str]) -> tuple[list[str], list[str]]:
    """Split detected languages into (CodeQL languages to run, languages skipped
    because they would need a build)."""
    run: list[str] = []
    for lang in detected:
        cq = NO_BUILD_LANGUAGES.get(lang)
        if cq and cq not in run:
            run.append(cq)
    skipped = [lang for lang in detected if lang in NEEDS_BUILD]
    return run, skipped


def _config_file(work_dir: Path) -> Path:
    """A CodeQL config that skips the same dependency/tool folders as everything else."""
    cfg = work_dir / "codeql-config.yml"
    lines = ["paths-ignore:"] + [f"  - '**/{d}/**'" for d in sorted(SKIP_DIRS)]
    cfg.write_text("\n".join(lines) + "\n")
    return cfg


def _run(cmd: list[str], timeout: int) -> None:
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=True)
    except subprocess.TimeoutExpired:
        raise CodeQLError(f"CodeQL took longer than {timeout}s") from None
    except subprocess.CalledProcessError as exc:
        raise CodeQLError(
            f"`{' '.join(cmd[1:3])}` failed (exit {exc.returncode}):\n{(exc.stderr or '').strip()[-2000:]}"
        ) from None


def run_codeql(
    source_root: Path, languages: list[str], work_dir: Path, timeout: int = 1800
) -> dict[str, dict[str, Any]]:
    """Build a CodeQL database per language and run the security-extended queries.

    Returns {language: parsed SARIF}. Databases are written under `work_dir`
    (pass a temporary folder; they are tens of MB and not needed afterwards).
    """
    exe = codeql_executable()
    if exe is None:
        raise CodeQLError("CodeQL is not installed (see README: CodeQL)")
    if not source_root.is_dir():
        raise CodeQLError(f"not a folder: {source_root}")
    work_dir.mkdir(parents=True, exist_ok=True)
    config = _config_file(work_dir)
    results: dict[str, dict[str, Any]] = {}
    for lang in languages:
        db = work_dir / f"db-{lang}"
        sarif = work_dir / f"{lang}.sarif"
        _run([
            exe, "database", "create", str(db),
            f"--language={lang}", "--build-mode=none",
            f"--source-root={source_root.resolve()}",
            f"--codescanning-config={config}",
            "--overwrite", "--quiet",
        ], timeout)
        _run([
            exe, "database", "analyze", str(db),
            f"codeql/{lang}-queries:codeql-suites/{lang}-security-extended.qls",
            "--format=sarif-latest", f"--output={sarif}",
            "--download",   # fetch the query pack if this CodeQL install lacks it
            "--threads=0",  # use all CPU cores
            "--quiet",
        ], timeout)
        try:
            results[lang] = json.loads(sarif.read_text())
        except (OSError, json.JSONDecodeError):
            raise CodeQLError(f"CodeQL produced no readable SARIF for {lang}") from None
    return results


# Converting SARIF into Findings


def _severity(rule: dict[str, Any], level: str | None) -> Severity:
    """Use the rule's numeric security-severity (0-10, as GitHub does), else the result level."""
    score = rule.get("properties", {}).get("security-severity")
    try:
        value = float(score)
    except (TypeError, ValueError):
        return {"error": Severity.HIGH, "warning": Severity.MEDIUM}.get(level or "", Severity.LOW)
    if value >= 9.0:
        return Severity.CRITICAL
    if value >= 7.0:
        return Severity.HIGH
    if value >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _rules_by_id(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Rule definitions live in the driver and, for query packs, in extensions."""
    tool = run.get("tool", {})
    components = [tool.get("driver", {})] + tool.get("extensions", [])
    return {r["id"]: r for c in components for r in c.get("rules", []) if "id" in r}


def _cwes(rule: dict[str, Any]) -> list[str]:
    tags = rule.get("properties", {}).get("tags", [])
    ids = {int(m.group(1)) for t in tags if (m := _CWE_TAG.search(t))}
    return [f"CWE-{i}" for i in sorted(ids)]


def _trace(result: dict[str, Any], base_dir: Path) -> list[TraceStep]:
    flows = result.get("codeFlows") or []
    if not flows:
        return []
    steps: list[TraceStep] = []
    for step in flows[0]["threadFlows"][0].get("locations", []):
        loc = step.get("location", {})
        phys = loc.get("physicalLocation", {})
        file = phys.get("artifactLocation", {}).get("uri")
        line = phys.get("region", {}).get("startLine")
        if not file or not line:
            continue
        if steps and (steps[-1].file, steps[-1].line) == (file, line):
            continue  # CodeQL often reports several nodes on one line; keep one
        note = loc.get("message", {}).get("text", "").replace("ControlFlowNode for ", "")
        code = read_snippet(base_dir, file, line, line).strip()
        steps.append(TraceStep(file=file, line=line, code=code, note=note))
    return steps


def to_findings(sarif: dict[str, Any], base_dir: Path) -> list[Finding]:
    """Convert one CodeQL SARIF file into Findings."""
    findings: list[Finding] = []
    seen: dict[str, int] = {}
    for run in sarif.get("runs", []):
        rules = _rules_by_id(run)
        for res in run.get("results", []):
            rule_id = res.get("ruleId") or res.get("rule", {}).get("id", "unknown")
            rule = rules.get(rule_id, {})
            props = rule.get("properties", {})
            phys = res["locations"][0]["physicalLocation"]
            file = phys["artifactLocation"]["uri"]
            region = phys.get("region", {})
            start = region.get("startLine", 1)
            end = region.get("endLine", start)
            snippet = read_snippet(base_dir, file, start, end)

            fp = fingerprint("codeql", rule_id, file, snippet)
            seen[fp] = seen.get(fp, 0) + 1
            if seen[fp] > 1:
                fp = f"{fp}-{seen[fp]}"

            findings.append(
                Finding(
                    fingerprint=fp,
                    scanner="codeql",
                    rule_id=rule_id,
                    message=_MD_LINK.sub(r"\1", res.get("message", {}).get("text", "")),
                    severity=_severity(rule, res.get("level")),
                    cwe=_cwes(rule),
                    location=Location(
                        file=file,
                        start_line=start,
                        end_line=end,
                        start_col=region.get("startColumn"),
                        end_col=region.get("endColumn"),
                    ),
                    snippet=snippet,
                    category="security" if "security" in props.get("tags", []) else None,
                    confidence=props.get("precision"),  # very-high / high / medium / low
                    references=[rule["helpUri"]] if rule.get("helpUri") else [],
                    trace=_trace(res, base_dir),
                )
            )
    return findings
