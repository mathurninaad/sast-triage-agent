import os
from pathlib import Path

import pytest

from sast_triage.context import tools as t
from sast_triage.context.repo import Repo, RepoError

DEMO_APP = Path(__file__).parent.parent / "examples" / "demo_app"


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "import db\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/items/<item_id>', methods=['GET', 'POST'])\n"
        "@login_required\n"
        "def show(item_id):\n"
        "    # db.lookup(item_id) in a comment does not count\n"
        "    s = 'lookup(x) in a string does not count'\n"
        "    return db.lookup(int(item_id))\n"
        "\n"
        "class Admin:\n"
        "    def lookup(self):\n"
        "        return lookup(1)\n"
    )
    (tmp_path / "db.py").write_text("def lookup(i):\n    return i\n")
    (tmp_path / "urls.py").write_text(
        "from django.urls import path\nfrom . import views\n"
        "urlpatterns = [path('report/', views.report)]\n"
    )
    (tmp_path / "views.py").write_text("def report(request):\n    return 1\n")
    (tmp_path / "long.txt").write_text("".join(f"row {i}\n" for i in range(1, 401)))
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "dep.py").write_text("def lookup():\n    pass\n")
    return Repo(tmp_path)


# Safety


def test_refuses_paths_outside_the_repo(repo, tmp_path):
    for bad in ("../secret.txt", "/etc/passwd", "a/../../x"):
        with pytest.raises(RepoError):
            repo.resolve(bad)


def test_refuses_symlink_escaping_the_repo(repo, tmp_path):
    outside = tmp_path.parent / "outside_secret.txt"
    outside.write_text("secret")
    os.symlink(outside, tmp_path / "link.txt")
    with pytest.raises(RepoError, match="outside"):
        t.read_file(repo, "link.txt")


def test_dependency_folders_are_invisible(repo):
    with pytest.raises(RepoError, match="dependency"):
        t.read_file(repo, ".venv/dep.py")
    assert ".venv" not in t.list_files(repo)
    assert ".venv" not in t.find_references(repo, "lookup")


# Tools


def test_list_files(repo):
    out = t.list_files(repo, "*.py")
    assert "app.py" in out and "db.py" in out and "long.txt" not in out


def test_read_file_numbers_and_caps(repo):
    out = t.read_file(repo, "long.txt", 10, 12)
    assert "10 | row 10" in out and "12 | row 12" in out and "row 13" not in out
    capped = t.read_file(repo, "long.txt", 1, 400)
    assert f"{t.MAX_READ_LINES} | row {t.MAX_READ_LINES}" in capped and "next range" in capped
    with pytest.raises(RepoError):
        t.read_file(repo, "long.txt", 500)
    with pytest.raises(RepoError):
        t.read_file(repo, "missing.py")


def test_search_code(repo):
    assert "app.py:10" in t.search_code(repo, "db.lookup(int")
    assert "views.py:1" in t.search_code(repo, r"def \w+\(request", regex=True)
    assert t.search_code(repo, "zzz-not-there").startswith("No matches")
    with pytest.raises(RepoError, match="invalid regex"):
        t.search_code(repo, "(", regex=True)


def test_get_function_includes_decorators(repo):
    out = t.get_function(repo, "show")
    assert "app.py:5-10 (show)" in out
    assert "@app.route" in out and "@login_required" in out and "int(item_id)" in out
    assert "(Admin.lookup)" in t.get_function(repo, "Admin.lookup")
    assert t.get_function(repo, "nope").startswith("No function")


def test_find_references_uses_ast(repo):
    out = t.find_references(repo, "lookup")
    assert "app.py:10 [call] in show" in out          # db.lookup(...)
    assert "app.py:14 [call] in Admin.lookup" in out  # lookup(1)
    assert "app.py:8" not in out and "app.py:9" not in out  # comment and string ignored
    assert "unused" in t.find_references(repo, "never_called")


def test_route_info_flask_and_django(repo):
    flask = t.get_route_info(repo, "show")
    assert "GET,POST /items/<item_id>" in flask
    assert "looks like an access check: @login_required" in flask
    django = t.get_route_info(repo, "report")
    assert "urls.py:3" in django and "path('report/', views.report)" in django
    assert "No route found" in t.get_route_info(repo, "lookup", file="db.py")


def test_output_is_capped(repo, tmp_path):
    (tmp_path / "big.py").write_text("".join(f"x_{i} = 'needle'\n" for i in range(3000)))
    out = t.search_code(repo, "needle", limit=5000)
    assert len(out) <= t.MAX_OUTPUT_CHARS + 100 and "output cut" in out


def test_demo_app_fp01_evidence():
    """The evidence the single-shot triage could not see for FP-01."""
    repo = Repo(DEMO_APP)
    refs = t.find_references(repo, "get_user_by_id")
    assert "app.py:35 [call] in get_user" in refs
    assert "uid = int(user_id)" in t.get_function(repo, "get_user")
