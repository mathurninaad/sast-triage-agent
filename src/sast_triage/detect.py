"""Detect which programming languages a repository uses.

Plain file counting, no AI: each file's extension (or name, for files like
Dockerfile) maps to a language. Folders that hold dependencies, build output
or tool caches are skipped, so a project's virtualenv or node_modules can't
make it look like a different language.
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

EXTENSION_LANGUAGES: dict[str, str] = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c", ".h": "c",
    ".cs": "csharp",
    ".kt": "kotlin", ".kts": "kotlin",
    ".scala": "scala",
    ".rs": "rust",
    ".swift": "swift",
    ".html": "html", ".htm": "html",
    ".tf": "terraform",
    ".sh": "bash", ".bash": "bash",
    ".yml": "yaml", ".yaml": "yaml",
    ".json": "json",
    ".sol": "solidity",
    ".ex": "elixir", ".exs": "elixir",
    ".ml": "ocaml", ".mli": "ocaml",
}

SKIP_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn",
    ".venv", "venv", "site-packages", "__pycache__",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "node_modules", "bower_components", ".next",
    "vendor", "build", "dist", "target",
    ".idea", ".vscode",
})


def language_of(filename: str) -> str | None:
    """Return the language of one file name, or None if we don't know it."""
    if filename == "Dockerfile" or filename.startswith("Dockerfile."):
        return "dockerfile"
    return EXTENSION_LANGUAGES.get(Path(filename).suffix.lower())


def count_languages(repo: Path) -> dict[str, int]:
    """Count source files per language, most common first."""
    if not repo.is_dir():
        raise NotADirectoryError(f"not a folder: {repo}")
    counts: Counter[str] = Counter()
    for _dirpath, dirnames, filenames in os.walk(repo):
        # Editing dirnames in place stops os.walk from going into those folders.
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if lang := language_of(name):
                counts[lang] += 1
    return dict(counts.most_common())


def detect_languages(repo: Path, min_files: int = 1) -> list[str]:
    """Languages with at least `min_files` files, most common first."""
    return [lang for lang, n in count_languages(repo).items() if n >= min_files]
