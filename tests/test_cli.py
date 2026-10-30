from typer.testing import CliRunner

from sast_triage import __version__
from sast_triage.cli import app

runner = CliRunner()


def test_version_command_prints_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_no_args_shows_help():
    result = runner.invoke(app, [])
    assert "Usage" in result.stdout
