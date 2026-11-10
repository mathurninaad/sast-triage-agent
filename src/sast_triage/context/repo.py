"""Safe, read-only access to the repository being investigated.

Every tool goes through Repo, so the safety rules live in one place:
- paths must resolve inside the repo root (no "..", absolute paths or
  symlinks that lead outside it);
- dependency, build and tool folders are invisible, as for the scanners;
- very large files are not read.
"""

from __future__ import annotations

import ast
import os
from functools import lru_cache
from pathlib import Path

from sast_triage.detect import SKIP_DIRS

MAX_FILE_BYTES = 1_000_000


class RepoError(ValueError):
    """A request the tools refuse (bad path, missing file, ...). Its message is
    shown to the agent, so it can correct itself."""


class Repo:
    def __init__(self, root: Path):
        self.root = root.resolve()
        if not self.root.is_dir():
            raise RepoError(f"not a folder: {root}")

    def resolve(self, rel_path: str) -> Path:
        """Turn a repo-relative path into a real path, refusing anything outside the repo."""
        if not rel_path or Path(rel_path).is_absolute():
            raise RepoError(f"use a path relative to the repository root, not {rel_path!r}")
        path = (self.root / rel_path).resolve()  # resolves ".." and symlinks
        if path != self.root and self.root not in path.parents:
            raise RepoError(f"{rel_path!r} is outside the repository")
        if any(part in SKIP_DIRS for part in path.relative_to(self.root).parts):
            raise RepoError(f"{rel_path!r} is in a dependency or tool folder, which is not analysed")
        return path

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def files(self, suffix: str | None = None) -> list[Path]:
        """All analysable files (optionally with one suffix), sorted, skipping SKIP_DIRS."""
        found: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                p = Path(dirpath) / name
                if (suffix is None or name.endswith(suffix)) and not p.is_symlink():
                    found.append(p)
        return found

    def read_lines(self, rel_path: str) -> list[str]:
        path = self.resolve(rel_path)
        if not path.is_file():
            raise RepoError(f"no such file: {rel_path}")
        if path.stat().st_size > MAX_FILE_BYTES:
            raise RepoError(f"{rel_path} is too large to read (over {MAX_FILE_BYTES // 1000} KB)")
        return path.read_text(errors="replace").splitlines()

    def parse(self, path: Path) -> ast.Module | None:
        """Parsed Python file, or None if it can't be parsed (cached per file version)."""
        try:
            stat = path.stat()
        except OSError:
            return None
        return _parse_cached(str(path), stat.st_mtime_ns, stat.st_size)


@lru_cache(maxsize=512)
def _parse_cached(path: str, _mtime: int, size: int) -> ast.Module | None:
    if size > MAX_FILE_BYTES:
        return None
    try:
        return ast.parse(Path(path).read_text(errors="replace"))
    except (SyntaxError, ValueError):
        return None
