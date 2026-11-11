"""Command-line entry point: `sast-triage ...`."""

import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from sast_triage import __version__
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


@app.command("semgrep")
def semgrep_baseline(
    target: Annotated[Path, typer.Argument(help="Folder or file to scan.")],
    config: Annotated[
        Optional[list[str]],
        typer.Option("--config", "-c", help="Semgrep ruleset or rules path. Repeatable."),
    ] = None,
    out: Annotated[
        Optional[Path], typer.Option(help="Where to save the raw JSON output.")
    ] = None,
) -> None:
    """Baseline: run Semgrep alone, save its raw output and summarise it."""
    configs = config or list(sg.DEFAULT_CONFIGS)
    console.print(f"Running Semgrep on [bold]{target}[/] with {', '.join(configs)} ...")
    try:
        output = sg.run_semgrep(target, configs)
    except sg.SemgrepError as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1) from None

    out = out or Path("reports") / f"semgrep-{target.resolve().name}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(output, indent=2))

    summary = sg.summarize(output)
    console.print(
        f"\nSemgrep {summary['version']}: [bold]{summary['results']}[/] results at "
        f"{summary['unique_locations']} unique locations, {summary['files_scanned']} files "
        f"scanned, {summary['errors']} errors, {summary['skipped_rules']} skipped rules"
    )
    for key in ("severity", "subcategory", "confidence", "cwe", "rule", "file"):
        table = Table(title=f"By {key}", title_justify="left")
        table.add_column(key)
        table.add_column("count", justify="right")
        for name, count in list(summary["by"][key].items())[:15]:
            table.add_row(name, str(count))
        console.print(table)
    console.print(f"Raw output saved to [bold]{out}[/]")
