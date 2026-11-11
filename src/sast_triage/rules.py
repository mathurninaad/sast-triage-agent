"""Download Semgrep's open-source rules and pick the folders for a repo's languages.

The rules (github.com/semgrep/semgrep-rules) are under the Semgrep Rules
License v1.0, which does not allow redistributing them. So they are never
copied into this repository: each user's machine downloads them straight
from Semgrep's repo, pinned to one commit, into a cache folder.
"""

from __future__ import annotations

import os
from pathlib import Path

from sast_triage import fetch

RULES_REPO = "https://github.com/semgrep/semgrep-rules.git"
# Pinned so every scan uses the same rules; bump deliberately.
RULES_COMMIT = "16b9e6d45f10649f6a531ec4838ed9924372c3bc"  # 2026-10-21

# Language (as named by detect.py) -> top-level folders in the rules repo.
# TypeScript code is also covered by most JavaScript rules.
LANGUAGE_RULE_DIRS: dict[str, tuple[str, ...]] = {
    "typescript": ("typescript", "javascript"),
}


class RulesError(RuntimeError):
    """The rules could not be downloaded."""


def default_cache_dir() -> Path:
    """Where downloads live: $SAST_TRIAGE_CACHE, else ~/.cache/sast-triage."""
    if custom := os.environ.get("SAST_TRIAGE_CACHE"):
        return Path(custom)
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "sast-triage"


def ensure_rules(cache_dir: Path | None = None, commit: str = RULES_COMMIT) -> Path:
    """Return the local rules folder, downloading it first if needed.

    A pinned commit never changes, so once downloaded it is reused as-is.
    """
    dest = (cache_dir or default_cache_dir()) / "semgrep-rules" / commit[:12]
    if fetch.is_complete(dest):
        return dest
    try:
        fetch.fetch_commit(RULES_REPO, dest, ref=commit)
    except fetch.FetchError as exc:
        raise RulesError(f"could not download Semgrep rules: {exc}") from None
    return dest


def rule_dirs_for(languages: list[str], rules_root: Path) -> list[Path]:
    """Rule folders for the given languages, skipping any the repo doesn't have."""
    dirs: list[Path] = []
    for lang in languages:
        for name in LANGUAGE_RULE_DIRS.get(lang, (lang,)):
            path = rules_root / name
            if path.is_dir() and path not in dirs:
                dirs.append(path)
    return dirs
