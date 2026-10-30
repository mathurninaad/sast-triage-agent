"""Command-line entry point: `sast-triage ...`."""

import typer

from sast_triage import __version__

app = typer.Typer(
    help="Run SAST scanners on a codebase and triage the findings with an AI agent.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """Keeps `sast-triage` as a command group so more commands can be added later."""


@app.command()
def version() -> None:
    """Print the installed version."""
    typer.echo(f"sast-triage {__version__}")
