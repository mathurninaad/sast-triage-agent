"""Command-line entry point: `sast-triage ...`."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from sast_triage import __version__, cache, detect, rules, targets
from sast_triage.scanners import bandit as bd
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
