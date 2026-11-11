import pytest
from typer.testing import CliRunner

from sast_triage import cache
from sast_triage.cli import app

runner = CliRunner()


@pytest.fixture
def fake_cache(tmp_path, monkeypatch):
    """A cache folder with one rules version and two repos."""
    root = tmp_path / "cache"
    rules = root / "semgrep-rules" / "16b9e6d45f10"
    rules.mkdir(parents=True)
    (rules / "rule.yaml").write_text("x" * 1000)
    (rules / ".sast-triage-complete").write_text("16b9e6d45f10649f6a531ec4838ed9924372c3bc")
    for owner, repo in (("alice", "app"), ("bob", "tool")):
        d = root / "repos" / owner / repo
        d.mkdir(parents=True)
        (d / "main.py").write_text("y" * 500)
        (d / ".sast-triage-complete").write_text("abc123")
    monkeypatch.setenv("SAST_TRIAGE_CACHE", str(root))
    return root


def test_human_size():
    assert cache.human_size(512) == "512 B"
    assert cache.human_size(1536) == "1.5 KB"
    assert cache.human_size(5 * 1024 * 1024) == "5.0 MB"


def test_entries(fake_cache):
    found = cache.entries(fake_cache)
    assert [(e.kind, e.name) for e in found] == [
        ("rules", "16b9e6d45f10"),
        ("repo", "alice/app"),
        ("repo", "bob/tool"),
    ]
    assert found[0].commit.startswith("16b9e6d")


def test_entries_empty(tmp_path):
    assert cache.entries(tmp_path / "nothing-here") == []


def test_clear_repos_only_keeps_rules(fake_cache):
    cache.clear(fake_cache, repos=True, rules=False)
    assert not (fake_cache / "repos").exists()
    assert (fake_cache / "semgrep-rules").exists()


def test_clear_all_removes_empty_cache_folder(fake_cache):
    cache.clear(fake_cache)
    assert not fake_cache.exists()


def test_clear_never_touches_unrelated_files(fake_cache):
    (fake_cache / "my-notes.txt").write_text("keep me")
    cache.clear(fake_cache)
    assert (fake_cache / "my-notes.txt").read_text() == "keep me"
    assert not (fake_cache / "repos").exists()


def test_cli_info(fake_cache):
    result = runner.invoke(app, ["cache", "info"])
    assert result.exit_code == 0
    assert "alice/app" in result.stdout and "Total" in result.stdout


def test_cli_clear_asks_and_can_be_cancelled(fake_cache):
    result = runner.invoke(app, ["cache", "clear"], input="n\n")
    assert "Cancelled" in result.stdout
    assert (fake_cache / "repos").exists()


def test_cli_clear_yes(fake_cache):
    result = runner.invoke(app, ["cache", "clear", "--repos-only", "--yes"])
    assert result.exit_code == 0 and "Freed" in result.stdout
    assert not (fake_cache / "repos").exists()
    assert (fake_cache / "semgrep-rules").exists()


def test_cli_clear_conflicting_flags(fake_cache):
    result = runner.invoke(app, ["cache", "clear", "--repos-only", "--rules-only"])
    assert result.exit_code == 1
