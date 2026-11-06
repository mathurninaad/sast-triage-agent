import pytest

from sast_triage import targets


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://github.com/adeyosemanputra/pygoat", ("adeyosemanputra", "pygoat")),
        ("https://github.com/owner/repo.git", ("owner", "repo")),
        ("https://github.com/owner/repo/", ("owner", "repo")),
        ("https://github.com/my-org/my.repo_2", ("my-org", "my.repo_2")),
    ],
)
def test_parse_github_url_valid(url, expected):
    assert targets.parse_github_url(url) == expected


@pytest.mark.parametrize(
    "text",
    [
        "examples/demo_app",
        "http://github.com/owner/repo",           # not https
        "https://gitlab.com/owner/repo",          # not GitHub
        "https://github.com/owner",               # no repo
        "https://github.com/owner/repo/tree/main",  # a page inside the repo
        "https://github.com/../etc",              # path traversal attempt
        "https://github.com/owner/..",
    ],
)
def test_parse_github_url_rejects(text):
    assert targets.parse_github_url(text) is None


def test_resolve_local_folder(tmp_path):
    t = targets.resolve_target(str(tmp_path))
    assert t.path == tmp_path and t.commit is None


def test_resolve_missing_folder(tmp_path):
    with pytest.raises(targets.TargetError, match="does not exist"):
        targets.resolve_target(str(tmp_path / "missing"))


def test_resolve_unsupported_url():
    with pytest.raises(targets.TargetError, match="unsupported URL"):
        targets.resolve_target("https://gitlab.com/owner/repo")


def test_ref_needs_a_url(tmp_path):
    with pytest.raises(targets.TargetError, match="--ref"):
        targets.resolve_target(str(tmp_path), ref="main")
