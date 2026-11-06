"""Download Semgrep's open-source rules and pick the folders for a repo's languages.

The rules (github.com/semgrep/semgrep-rules) are under the Semgrep Rules
License v1.0, which does not allow redistributing them. So they are never
copied into this repository: each user's machine downloads them straight
from Semgrep's repo, pinned to one commit, into a cache folder.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

RULES_REPO = "https://github.com/semgrep/semgrep-rules.git"
# Pinned so every scan uses the same rules; bump deliberately.
RULES_COMMIT = "16b9e6d45f10649f6a531ec4838ed9924372c3bc"  # 2026-10-21

# Language (as named by detect.py) -> top-level folders in the rules repo.
# TypeScript code is also covered by most JavaScript rules.
LANGUAGE_RULE_DIRS: dict[str, tuple[str, ...]] = {
    "typescript": ("typescript", "javascript"),
}

_COMPLETE_MARKER = ".sast-triage-complete"


class RulesError(RuntimeError):
    """The rules could not be downloaded."""


def default_cache_dir() -> Path:
    """Where downloaded rules live: $SAST_TRIAGE_CACHE, else ~/.cache/sast-triage."""
    if custom := os.environ.get("SAST_TRIAGE_CACHE"):
        return Path(custom)
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "sast-triage"


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True, timeout=600)


def ensure_rules(cache_dir: Path | None = None, commit: str = RULES_COMMIT) -> Path:
    """Return the local rules folder, downloading it first if needed.

    Only the pinned commit is fetched (no history). A marker file is written
    last, so a download that was interrupted is detected and redone.
    """
    dest = (cache_dir or default_cache_dir()) / "semgrep-rules" / commit[:12]
    if (dest / _COMPLETE_MARKER).exists():
        return dest
    if dest.exists():
        shutil.rmtree(dest)  # leftover from an interrupted download
    dest.mkdir(parents=True)
    try:
        _git("init", "--quiet", cwd=dest)
        _git("fetch", "--quiet", "--depth", "1", RULES_REPO, commit, cwd=dest)
        _git("checkout", "--quiet", "FETCH_HEAD", cwd=dest)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        shutil.rmtree(dest, ignore_errors=True)
        detail = getattr(exc, "stderr", "") or str(exc)
        raise RulesError(f"could not download Semgrep rules: {detail.strip()}") from None
    (dest / _COMPLETE_MARKER).touch()
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
