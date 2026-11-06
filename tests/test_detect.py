from pathlib import Path

import pytest

from sast_triage import detect

DEMO_APP = Path(__file__).parent.parent / "examples" / "demo_app"


def _touch(root: Path, *paths: str) -> None:
    for p in paths:
        f = root / p
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("")


def test_language_of():
    assert detect.language_of("app.py") == "python"
    assert detect.language_of("Main.JAVA") == "java"  # extensions are case-insensitive
    assert detect.language_of("Dockerfile") == "dockerfile"
    assert detect.language_of("Dockerfile.dev") == "dockerfile"
    assert detect.language_of("notes.md") is None


def test_counts_and_order(tmp_path):
    _touch(tmp_path, "a.py", "b.py", "pkg/c.py", "web/index.html", "deploy.yml")
    assert detect.count_languages(tmp_path) == {"python": 3, "html": 1, "yaml": 1}
    assert detect.detect_languages(tmp_path)[0] == "python"


def test_skips_dependency_and_tool_folders(tmp_path):
    _touch(
        tmp_path,
        "app.py",
        ".venv/lib/site-packages/lib.py",
        "node_modules/lodash/index.js",
        ".git/hooks/pre-commit.sh",
    )
    assert detect.count_languages(tmp_path) == {"python": 1}


def test_min_files(tmp_path):
    _touch(tmp_path, "a.py", "b.py", "c.js")
    assert detect.detect_languages(tmp_path, min_files=2) == ["python"]


def test_not_a_folder(tmp_path):
    with pytest.raises(NotADirectoryError):
        detect.count_languages(tmp_path / "missing")


def test_demo_app():
    # Only the app's own code: the answer key lives in eval/labels/, not here.
    assert detect.count_languages(DEMO_APP) == {"python": 2}
