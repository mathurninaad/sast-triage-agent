"""Command-line entry point: `sast-triage ...`."""

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from dotenv import load_dotenv

from sast_triage import __version__, cache, dedupe, detect, evaluate, rules, targets, triage
from sast_triage.models import Candidate
from sast_triage.scanners import bandit as bd
from sast_triage.scanners import codeql as cq
from sast_triage.scanners import semgrep as sg

app = typer.Typer(
    help="Run SAST scanners on a codebase and triage the findings with an AI agent.",
    no_args_is_help=True,
)
console = Console()

cache_app = typer.Typer(help="Inspect or clear downloaded rules and repos.", no_args_is_help=True)
app.add_typer(cache_app, name="cache")


@app.callback()
def main() -> None:
    """Keeps `sast-triage` as a command group so more commands can be added later."""
    load_dotenv()  # read API keys from a .env file in the current folder, if there is one


@app.command()
def version() -> None:
    """Print the installed version."""
    typer.echo(f"sast-triage {__version__}")


TargetArg = Annotated[str, typer.Argument(help="Folder, file, or https://github.com/owner/repo URL.")]
RefOpt = Annotated[
    Optional[str],
    typer.Option(help="Branch, tag or commit to scan (GitHub URLs only). Default: the default branch."),
]


def _resolve(target: str, ref: Optional[str]) -> targets.Target:
    """Turn the user's target into a local folder, downloading it if it's a URL."""
    if targets.parse_github_url(target):
        console.print(f"Fetching [bold]{target}[/]{f' at {ref}' if ref else ''} ...")
    try:
        resolved = targets.resolve_target(target, ref)
    except targets.TargetError as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1) from None
    if resolved.commit:
        console.print(f"Got {resolved.source} at commit [bold]{resolved.commit[:12]}[/]")
    return resolved


@app.command()
def languages(target: TargetArg, ref: RefOpt = None) -> None:
    """Show the languages detected in a folder or repo and the rule folders they map to."""
    resolved = _resolve(target, ref)
    if not resolved.path.is_dir():
        console.print(f"[red]Error:[/] not a folder: {target}")
        raise typer.Exit(code=1)
    counts = detect.count_languages(resolved.path)
    if not counts:
        console.print("No supported languages found.")
        return
    table = Table(title=f"Languages in {resolved.source}", title_justify="left")
    table.add_column("language")
    table.add_column("files", justify="right")
    table.add_column("rule folders")
    for lang, n in counts.items():
        folders = ", ".join(rules.LANGUAGE_RULE_DIRS.get(lang, (lang,)))
        table.add_row(lang, str(n), folders)
    console.print(table)


def _auto_configs(target: Path) -> tuple[list[str], list[str]]:
    """Detect the target's languages and return the matching rule folders."""
    scan_root = target if target.is_dir() else target.parent
    langs = detect.detect_languages(scan_root)
    if not langs:
        console.print("[red]Error:[/] no supported languages found to pick rules for.")
        raise typer.Exit(code=1)
    console.print(f"Detected languages: [bold]{', '.join(langs)}[/]")
    try:
        rules_root = rules.ensure_rules()
    except rules.RulesError as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1) from None
    dirs = rules.rule_dirs_for(langs, rules_root)
    if not dirs:
        console.print("[red]Error:[/] the rules repo has no folders for these languages.")
        raise typer.Exit(code=1)
    console.print(f"Using rules from {rules_root}: {', '.join(d.name for d in dirs)}")
    return [str(d) for d in dirs], langs


def _print_summary(scanner: str, summary: dict) -> None:
    """Headline counts plus one table per dimension in summary["by"]."""
    version = f" {summary['version']}" if summary.get("version") else ""
    console.print(
        f"\n{scanner}{version}: [bold]{summary['results']}[/] results at "
        f"{summary['unique_locations']} unique locations, {summary['files_scanned']} files "
        f"scanned, {summary['errors']} errors, {summary['skipped_rules']} skipped rules"
    )
    for key, counts in summary["by"].items():
        table = Table(title=f"By {key}", title_justify="left")
        table.add_column(key)
        table.add_column("count", justify="right")
        for name, count in list(counts.items())[:15]:
            table.add_row(name, str(count))
        console.print(table)


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


@app.command("semgrep")
def semgrep_baseline(
    target: TargetArg,
    ref: RefOpt = None,
    config: Annotated[
        Optional[list[str]],
        typer.Option(
            "--config", "-c",
            help="Semgrep ruleset or rules path. Repeatable. "
            "If omitted, rules are picked from the detected languages.",
        ),
    ] = None,
    all_categories: Annotated[
        bool,
        typer.Option("--all-categories", help="Also count non-security results in the summary."),
    ] = False,
    out: Annotated[
        Optional[Path], typer.Option(help="Where to save the raw JSON output.")
    ] = None,
) -> None:
    """Baseline: run Semgrep alone, save its raw output and summarise it."""
    resolved = _resolve(target, ref)
    detected: list[str] = []
    if config:
        configs = config
    else:
        configs, detected = _auto_configs(resolved.path)
    console.print(f"Running Semgrep on [bold]{resolved.source}[/] ...")
    try:
        output = sg.run_semgrep(resolved.path, configs)
    except sg.SemgrepError as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1) from None

    # The raw file is always Semgrep's complete, unfiltered output.
    out = out or Path("reports") / f"semgrep-{resolved.name}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(output, indent=2))
    # Alongside it: what exactly was scanned, so the result can be reproduced.
    meta = {
        "target": resolved.source,
        "commit": resolved.commit,
        "ref": ref,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "semgrep_version": output.get("version"),
        "configs": config or "auto",
        "detected_languages": detected,
        "rules_commit": None if config else rules.RULES_COMMIT,
        "sast_triage_version": __version__,
    }
    out.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2))

    shown, dropped = (output, 0) if all_categories else sg.security_only(output)

    # Our own format: one Finding per result, with snippet and stable fingerprint.
    base_dir = resolved.path if resolved.path.is_dir() else resolved.path.parent
    findings = sg.to_findings(shown, base_dir, configs)
    findings_out = out.with_name(out.name.replace("semgrep-", "findings-", 1))
    if findings_out == out:
        findings_out = out.with_suffix(".findings.json")
    findings_out.write_text(
        json.dumps([f.model_dump(mode="json") for f in findings], indent=2)
    )

    _print_summary("Semgrep", sg.summarize(shown))
    if dropped:
        console.print(
            f"({dropped} code-quality results left out; use --all-categories to include them)"
        )
    console.print(f"Raw output saved to [bold]{out}[/]")
    console.print(f"{len(findings)} findings saved to [bold]{findings_out}[/]")


@cache_app.command("info")
def cache_info() -> None:
    """Show what's in the download cache and how much space it uses."""
    root = rules.default_cache_dir()
    found = cache.entries(root)
    console.print(f"Cache folder: [bold]{root}[/]")
    if not found:
        console.print("The cache is empty.")
        return
    table = Table(title_justify="left")
    table.add_column("kind")
    table.add_column("name")
    table.add_column("commit")
    table.add_column("size", justify="right")
    for e in found:
        table.add_row(e.kind, e.name, (e.commit or "-")[:12], cache.human_size(e.size_bytes))
    console.print(table)
    total = sum(e.size_bytes for e in found)
    console.print(f"Total: [bold]{cache.human_size(total)}[/]")


@cache_app.command("clear")
def cache_clear(
    repos_only: Annotated[bool, typer.Option("--repos-only", help="Keep the rules, delete fetched repos.")] = False,
    rules_only: Annotated[bool, typer.Option("--rules-only", help="Keep repos, delete the rules.")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Don't ask for confirmation.")] = False,
) -> None:
    """Delete downloaded rules and/or repos. They are downloaded again when needed."""
    if repos_only and rules_only:
        console.print("[red]Error:[/] choose at most one of --repos-only and --rules-only.")
        raise typer.Exit(code=1)
    root = rules.default_cache_dir()
    clear_repos, clear_rules = not rules_only, not repos_only
    chosen = [
        e for e in cache.entries(root)
        if (e.kind == "repo" and clear_repos) or (e.kind == "rules" and clear_rules)
    ]
    if not chosen:
        console.print("Nothing to clear.")
        return
    size = cache.human_size(sum(e.size_bytes for e in chosen))
    what = "repos" if repos_only else "rules" if rules_only else "rules and repos"
    if not yes and not typer.confirm(f"Delete cached {what} ({len(chosen)} items, {size}) in {root}?"):
        console.print("Cancelled.")
        raise typer.Exit()
    freed = cache.clear(root, repos=clear_repos, rules=clear_rules)
    console.print(f"Freed {cache.human_size(freed)}.")


@app.command("bandit")
def bandit_baseline(
    target: TargetArg,
    ref: RefOpt = None,
    out: Annotated[
        Optional[Path], typer.Option(help="Where to save the raw JSON output.")
    ] = None,
) -> None:
    """Baseline: run Bandit (Python only) alone, save its output and summarise it."""
    resolved = _resolve(target, ref)
    console.print(f"Running Bandit on [bold]{resolved.source}[/] ...")
    try:
        output = bd.run_bandit(resolved.path)
    except bd.BanditError as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1) from None

    out = out or Path("reports") / f"bandit-{resolved.name}.json"
    _write_json(out, output)
    _write_json(out.with_suffix(".meta.json"), {
        "target": resolved.source,
        "commit": resolved.commit,
        "ref": ref,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scanner": "bandit",
        "sast_triage_version": __version__,
    })
    base_dir = resolved.path if resolved.path.is_dir() else resolved.path.parent
    findings = bd.to_findings(output, base_dir)
    findings_out = out.with_name(out.name.replace("bandit-", "findings-bandit-", 1))
    if findings_out == out:
        findings_out = out.with_suffix(".findings.json")
    _write_json(findings_out, [f.model_dump(mode="json") for f in findings])

    _print_summary("Bandit", bd.summarize(output))
    console.print(f"Raw output saved to [bold]{out}[/]")
    console.print(f"{len(findings)} findings saved to [bold]{findings_out}[/]")


def _run_codeql_step(
    base_dir: Path, langs: list[str], out_dir: Path, findings: list, counts: dict, skip: bool
) -> str:
    """Run CodeQL for the languages it can analyse without a build.

    Appends to `findings` and `counts` in place; returns a status for meta.json.
    """
    if skip:
        return "skipped (--no-codeql)"
    run_langs, needs_build = cq.plan_languages(langs)
    if needs_build:
        console.print(
            f"[yellow]CodeQL: skipping {', '.join(needs_build)}[/] (analysing it means "
            "running the project's build scripts, which this tool never does)"
        )
    if not run_langs:
        return "no supported languages"
    if cq.codeql_executable() is None:
        console.print(
            "[yellow]CodeQL is not installed, so it was skipped.[/] It's the scanner that "
            "traces data across files; see the README section 'CodeQL' to install it."
        )
        return "not installed"
    console.print(f"Running CodeQL ({', '.join(run_langs)}) ...")
    console.print(f"[dim]{cq.LICENSE_NOTICE}[/]")
    try:
        with tempfile.TemporaryDirectory(prefix="sast-triage-codeql-") as work:
            sarifs = cq.run_codeql(base_dir, run_langs, Path(work))
    except cq.CodeQLError as exc:
        console.print(f"[red]CodeQL failed:[/] {exc}")
        return "failed"
    total = 0
    for lang, sarif in sarifs.items():
        _write_json(out_dir / f"codeql-{lang}.sarif", sarif)
        cq_findings = cq.to_findings(sarif, base_dir)
        findings += cq_findings
        total += len(cq_findings)
    counts["codeql"] = total
    return f"ran: {', '.join(run_langs)}"


@app.command()
def scan(
    target: TargetArg,
    ref: RefOpt = None,
    config: Annotated[
        Optional[list[str]],
        typer.Option("--config", "-c", help="Semgrep rules instead of automatic selection. Repeatable."),
    ] = None,
    out_dir: Annotated[
        Optional[Path], typer.Option("--out-dir", help="Folder for this scan's files. Default: reports/<name>/")
    ] = None,
    no_codeql: Annotated[
        bool, typer.Option("--no-codeql", help="Skip CodeQL (e.g. for private code; see its licence).")
    ] = False,
) -> None:
    """Run all scanners, merge their findings into candidates, and save everything.

    This is the pipeline up to triage: Semgrep, Bandit (Python), CodeQL
    (if installed), conversion to Findings, then dedupe into one candidate
    per location.
    """
    resolved = _resolve(target, ref)
    base_dir = resolved.path if resolved.path.is_dir() else resolved.path.parent
    langs = detect.detect_languages(base_dir)
    if config:
        configs = config
    else:
        configs, langs = _auto_configs(resolved.path)

    out_dir = out_dir or Path("reports") / resolved.name
    findings = []
    counts: dict[str, int] = {}

    console.print(f"Running Semgrep on [bold]{resolved.source}[/] ...")
    try:
        sg_raw = sg.run_semgrep(resolved.path, configs)
    except sg.SemgrepError as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1) from None
    _write_json(out_dir / "semgrep.json", sg_raw)
    sg_shown, dropped = sg.security_only(sg_raw)
    sg_findings = sg.to_findings(sg_shown, base_dir, configs)
    findings += sg_findings
    counts["semgrep"] = len(sg_findings)

    if "python" in langs:
        console.print("Running Bandit ...")
        try:
            bd_raw = bd.run_bandit(resolved.path)
        except bd.BanditError as exc:
            console.print(f"[red]Error:[/] {exc}")
            raise typer.Exit(code=1) from None
        _write_json(out_dir / "bandit.json", bd_raw)
        bd_findings = bd.to_findings(bd_raw, base_dir)
        findings += bd_findings
        counts["bandit"] = len(bd_findings)

    codeql_status = _run_codeql_step(base_dir, langs, out_dir, findings, counts, skip=no_codeql)

    candidates = dedupe.group_findings(findings, base_dir)
    _write_json(out_dir / "findings.json", [f.model_dump(mode="json") for f in findings])
    _write_json(out_dir / "candidates.json", [c.model_dump(mode="json") for c in candidates])
    _write_json(out_dir / "meta.json", {
        "target": resolved.source,
        "commit": resolved.commit,
        "ref": ref,
        "source_root": str(base_dir.resolve()),
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "detected_languages": langs,
        "semgrep_version": sg_raw.get("version"),
        "semgrep_configs": config or "auto",
        "rules_commit": None if config else rules.RULES_COMMIT,
        "findings_per_scanner": counts,
        "codeql": codeql_status,
        "semgrep_code_quality_dropped": dropped,
        "candidates": len(candidates),
        "sast_triage_version": __version__,
    })

    per_scanner = ", ".join(f"{n} from {s}" for s, n in counts.items())
    console.print(
        f"\n[bold]{len(findings)}[/] findings ({per_scanner}) merged into "
        f"[bold]{len(candidates)}[/] candidates"
    )
    table = Table(title_justify="left")
    table.add_column("location")
    table.add_column("cwe")
    table.add_column("severity")
    table.add_column("scanners")
    table.add_column("findings", justify="right")
    for cand in candidates:
        lines = f"{cand.start_line}" if cand.start_line == cand.end_line else f"{cand.start_line}-{cand.end_line}"
        table.add_row(
            f"{cand.file}:{lines}", ", ".join(cand.cwe) or "-", cand.severity.value,
            "+".join(cand.scanners), str(len(cand.findings)),
        )
    console.print(table)
    console.print(f"Saved to [bold]{out_dir}/[/] (candidates.json, findings.json, raw outputs, meta.json)")


def _load_scan(scan_dir: Path) -> tuple[list[Candidate], Path]:
    """Candidates from a `scan` output folder, and the folder their code lives in."""
    cand_file, meta_file = scan_dir / "candidates.json", scan_dir / "meta.json"
    if not cand_file.exists() or not meta_file.exists():
        console.print(f"[red]Error:[/] {scan_dir} has no candidates.json/meta.json; run `sast-triage scan` first.")
        raise typer.Exit(code=1)
    candidates = [Candidate.model_validate(c) for c in json.loads(cand_file.read_text())]
    source_root = Path(json.loads(meta_file.read_text()).get("source_root", ""))
    if not source_root.is_dir():
        console.print(f"[red]Error:[/] the scanned code is no longer at {source_root}; scan again.")
        raise typer.Exit(code=1)
    return candidates, source_root


ScanDirArg = Annotated[Path, typer.Argument(help="A scan output folder, e.g. reports/demo_app")]


@app.command("triage")
def triage_cmd(
    scan_dir: ScanDirArg,
    model: Annotated[str, typer.Option(help="Groq model ID.")] = triage.DEFAULT_MODEL,
) -> None:
    """Ask an LLM for a verdict on each candidate (single-shot baseline, no tools)."""
    candidates, source_root = _load_scan(scan_dir)
    try:
        judge = triage.groq_judge(model)
    except RuntimeError as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1) from None

    verdicts = []
    with console.status("Triaging...") as status:
        for i, cand in enumerate(candidates, 1):
            status.update(f"Triaging {i}/{len(candidates)}: {cand.file}:{cand.start_line}")
            verdicts.append(triage.triage_candidate(cand, source_root, judge, model))
    _write_json(scan_dir / "verdicts.json", [v.model_dump(mode="json") for v in verdicts])

    table = Table(title=f"Verdicts ({model})", title_justify="left")
    for col in ("location", "verdict", "conf", "reasoning"):
        table.add_column(col)
    colours = {"true_positive": "red", "false_positive": "green", "needs_review": "yellow"}
    for v in verdicts:
        lines = f"{v.start_line}" if v.start_line == v.end_line else f"{v.start_line}-{v.end_line}"
        table.add_row(
            f"{v.file}:{lines}",
            f"[{colours[v.verdict]}]{v.verdict}[/]",
            f"{v.confidence:.2f}",
            (v.error or v.reasoning)[:120],
        )
    console.print(table)
    errors = sum(1 for v in verdicts if v.error)
    if errors:
        console.print(f"[yellow]{errors} candidates could not be triaged (kept as needs_review).[/]")
    console.print(f"Saved to [bold]{scan_dir / 'verdicts.json'}[/]")


@app.command("evaluate")
def evaluate_cmd(
    scan_dir: ScanDirArg,
    labels: Annotated[Path, typer.Option(help="Ground-truth label file.")],
) -> None:
    """Score a scan's verdicts against ground-truth labels."""
    candidates, _ = _load_scan(scan_dir)
    verdict_file = scan_dir / "verdicts.json"
    verdicts = (
        [triage.Verdict.model_validate(v) for v in json.loads(verdict_file.read_text())]
        if verdict_file.exists() else []
    )
    if not verdicts:
        console.print("[yellow]No verdicts.json yet: showing the scanners-only baseline.[/]")
    result = evaluate.evaluate(candidates, verdicts, evaluate.load_labels(labels))

    table = Table(title_justify="left")
    for col in ("location", "label", "truth", "verdict", ""):
        table.add_column(col)
    for r in result["rows"]:
        c = r.candidate
        lines = f"{c.start_line}" if c.start_line == c.end_line else f"{c.start_line}-{c.end_line}"
        mark = {True: "[green]ok[/]", False: "[red]wrong[/]", None: ""}[r.correct]
        table.add_row(
            f"{c.file}:{lines}", r.label["id"] if r.label else "-", r.truth,
            r.verdict.verdict if r.verdict else "-", mark,
        )
    console.print(table)

    summary = Table(title="Scores", title_justify="left")
    summary.add_column("metric")
    summary.add_column("scanners only", justify="right")
    if verdicts:
        summary.add_column("after triage", justify="right")
    base, tri = result["baseline"], result["triage"]
    rows = [
        ("candidates shown to user", "candidates_kept"),
        ("real bugs kept (of those scanned)", None),
        ("recall, end to end", "recall_end_to_end"),
        ("false alarms removed", "false_alarms_removed"),
        ("precision", "precision"),
    ]
    for name, key in rows:
        if key is None:
            vals = [f"{m['real_kept']}/{m['real_candidates']}" for m in (base, tri)]
        else:
            vals = ["-" if m[key] is None else str(m[key]) for m in (base, tri)]
        summary.add_row(name, *(vals if verdicts else vals[:1]))
    console.print(summary)
    if result["missed_by_scanners"]:
        console.print(f"Missed by every scanner (triage can't recover these): {', '.join(result['missed_by_scanners'])}")
    if result["needs_review"]:
        console.print(f"{result['needs_review']} candidates marked needs_review (kept for a human).")
