"""Inspect and clear the download cache (Semgrep rules and fetched repos).

Downloads live outside the project (see rules.default_cache_dir) and are
kept between runs so they aren't downloaded again. Nothing removes them
automatically; these helpers back the `sast-triage cache` commands.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from sast_triage.rules import default_cache_dir

# The only folders this tool creates inside the cache. Clearing touches
# nothing else, so a cache path set by mistake to a folder with other
# files in it can't lose those files.
RULES_DIR = "semgrep-rules"
REPOS_DIR = "repos"
_MARKER = ".sast-triage-complete"


@dataclass(frozen=True)
class Entry:
    kind: str            # "rules" or "repo"
    name: str            # rules version folder, or "owner/repo"
    path: Path
    size_bytes: int
    commit: str | None   # recorded commit, if known


def folder_size(path: Path) -> int:
    """Total size in bytes of the files under `path` (symlinks not followed)."""
    if not path.exists():
        return 0
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file() and not f.is_symlink())


def human_size(n: int) -> str:
    """1536 -> '1.5 KB'."""
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"  # unreachable; keeps type checkers happy


def _commit_of(folder: Path) -> str | None:
    marker = folder / _MARKER
    if marker.exists():
        text = marker.read_text().strip()
        return text or None
    return None


def entries(cache_dir: Path | None = None) -> list[Entry]:
    """Everything currently in the cache: rules versions first, then repos."""
    root = cache_dir or default_cache_dir()
    found: list[Entry] = []
    rules_root = root / RULES_DIR
    if rules_root.is_dir():
        for version in sorted(p for p in rules_root.iterdir() if p.is_dir()):
            found.append(Entry("rules", version.name, version, folder_size(version), _commit_of(version)))
    repos_root = root / REPOS_DIR
    if repos_root.is_dir():
        for owner in sorted(p for p in repos_root.iterdir() if p.is_dir()):
            for repo in sorted(p for p in owner.iterdir() if p.is_dir()):
                found.append(
                    Entry("repo", f"{owner.name}/{repo.name}", repo, folder_size(repo), _commit_of(repo))
                )
    return found


def clear(cache_dir: Path | None = None, *, repos: bool = True, rules: bool = True) -> int:
    """Delete cached repos and/or rules. Returns the number of bytes freed."""
    root = cache_dir or default_cache_dir()
    freed = 0
    for wanted, name in ((rules, RULES_DIR), (repos, REPOS_DIR)):
        target = root / name
        if wanted and target.exists():
            freed += folder_size(target)
            shutil.rmtree(target)
    # Remove the cache folder itself only if that left it empty.
    if root.is_dir() and not any(root.iterdir()):
        root.rmdir()
    return freed
