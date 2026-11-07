import subprocess

import pytest

from sast_triage import fetch


def _git(*args, cwd):
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=cwd, check=True, capture_output=True,
    )


@pytest.fixture
def source_repo(tmp_path):
    """A tiny local git repo with two commits, standing in for GitHub."""
    repo = tmp_path / "source"
    repo.mkdir()
    _git("init", "-q", "-b", "main", cwd=repo)
    (repo / "app.py").write_text("print('v1')\n")
    _git("add", ".", cwd=repo)
    _git("commit", "-q", "-m", "v1", cwd=repo)
    (repo / "app.py").write_text("print('v2')\n")
    _git("commit", "-q", "-am", "v2", cwd=repo)
    return repo


def _rev(repo, ref):
    return subprocess.run(
        ["git", "rev-parse", ref], cwd=repo, capture_output=True, text=True, check=True
    ).stdout.strip()


def test_fetch_latest(source_repo, tmp_path):
    dest = tmp_path / "dest"
    commit = fetch.fetch_commit(str(source_repo), dest)
    assert commit == _rev(source_repo, "HEAD")
    assert (dest / "app.py").read_text() == "print('v2')\n"
    assert fetch.is_complete(dest)


def test_fetch_is_shallow(source_repo, tmp_path):
    dest = tmp_path / "dest"
    fetch.fetch_commit(str(source_repo), dest)
    log = subprocess.run(["git", "log", "--oneline"], cwd=dest, capture_output=True, text=True)
    assert len(log.stdout.strip().splitlines()) == 1  # only the latest commit, no history


def test_fetch_specific_commit(source_repo, tmp_path):
    first = _rev(source_repo, "HEAD~1")
    dest = tmp_path / "dest"
    assert fetch.fetch_commit(str(source_repo), dest, ref=first) == first
    assert (dest / "app.py").read_text() == "print('v1')\n"


def test_refetch_updates_in_place(source_repo, tmp_path):
    dest = tmp_path / "dest"
    first = _rev(source_repo, "HEAD~1")
    fetch.fetch_commit(str(source_repo), dest, ref=first)
    fetch.fetch_commit(str(source_repo), dest)  # now the latest
    assert (dest / "app.py").read_text() == "print('v2')\n"


def test_bad_url_cleans_up(tmp_path):
    dest = tmp_path / "dest"
    with pytest.raises(fetch.FetchError, match="could not download"):
        fetch.fetch_commit(str(tmp_path / "no-such-repo"), dest)
    assert not dest.exists()


def test_size_limit(source_repo, tmp_path):
    dest = tmp_path / "dest"
    with pytest.raises(fetch.FetchError, match="over the"):
        fetch.fetch_commit(str(source_repo), dest, max_mb=0.000001)
    assert not dest.exists()


def test_failed_refetch_keeps_existing_copy(source_repo, tmp_path):
    dest = tmp_path / "dest"
    good = fetch.fetch_commit(str(source_repo), dest)
    with pytest.raises(fetch.FetchError, match="no branch, tag or commit"):
        fetch.fetch_commit(str(source_repo), dest, ref="no-such-branch")
    # the earlier good copy is still there and still marked complete
    assert (dest / "app.py").read_text() == "print('v2')\n"
    assert fetch.is_complete(dest)
    assert (dest / ".sast-triage-complete").read_text() == good


def test_failed_first_fetch_removes_empty_parent(tmp_path):
    dest = tmp_path / "repos" / "someone" / "missing"
    with pytest.raises(fetch.FetchError):
        fetch.fetch_commit(str(tmp_path / "no-such-repo"), dest)
    assert not (tmp_path / "repos" / "someone").exists()
