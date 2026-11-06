"""Command-line entry point: `sast-triage ...`."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from sast_triage import __version__, detect, rules, targets
from sast_triage.scanners import semgrep as sg

app = typer.Typer(
    help="Run SAST scanners on a codebase and triage the findings with an AI agent.",
    no_args_is_help=True,
)
console = Console()


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
    summary = sg.summarize(shown)
    console.print(
        f"\nSemgrep {summary['version']}: [bold]{summary['results']}[/] results at "
        f"{summary['unique_locations']} unique locations, {summary['files_scanned']} files "
        f"scanned, {summary['errors']} errors, {summary['skipped_rules']} skipped rules"
    )
    if dropped:
        console.print(
            f"({dropped} code-quality results left out; use --all-categories to include them)"
        )
    for key in ("severity", "subcategory", "confidence", "cwe", "rule", "file"):
        table = Table(title=f"By {key}", title_justify="left")
        table.add_column(key)
        table.add_column("count", justify="right")
        for name, count in list(summary["by"][key].items())[:15]:
            table.add_row(name, str(count))
        console.print(table)
    console.print(f"Raw output saved to [bold]{out}[/]")
