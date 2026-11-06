"""Download a git repository at one commit (shallow), for scanning.

Shared by the rules download (rules.py) and GitHub URL targets (targets.py).
Only the requested commit is fetched, never the history, and nothing in the
downloaded repo is ever executed: git does not run a repo's hooks on fetch,
and scanners only read files.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

# Refuse repos bigger than this after download, so a huge repo can't fill the disk.
DEFAULT_MAX_MB = 500

_MARKER = ".sast-triage-complete"


class FetchError(RuntimeError):
    """The repository could not be downloaded."""


def _git(*args: str, cwd: Path, timeout: int) -> str:
    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",   # private/missing repo: fail instead of asking for a password
        "GIT_LFS_SKIP_SMUDGE": "1",   # don't pull large binary files stored in Git LFS
    }
    proc = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *args],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout, check=True,
    )
    return proc.stdout.strip()


def _size_mb(folder: Path) -> float:
    total = sum(f.stat().st_size for f in folder.rglob("*") if f.is_file() and not f.is_symlink())
    return total / (1024 * 1024)


def is_complete(dest: Path) -> bool:
    """True if `dest` holds a finished download."""
    return (dest / _MARKER).exists()


def fetch_commit(
    url: str,
    dest: Path,
    ref: str | None = None,
    timeout: int = 600,
    max_mb: float = DEFAULT_MAX_MB,
) -> str:
    """Fetch `ref` (default: the repo's default branch) of `url` into `dest`.

    Re-fetching into an existing `dest` updates it in place; git only
    downloads what changed. Returns the full commit hash that was checked out.
    """
    dest.mkdir(parents=True, exist_ok=True)
    (dest / _MARKER).unlink(missing_ok=True)  # incomplete until we finish
    try:
        if not (dest / ".git").exists():
            _git("init", "--quiet", cwd=dest, timeout=timeout)
        _git("fetch", "--quiet", "--depth", "1", url, ref or "HEAD", cwd=dest, timeout=timeout)
        _git("checkout", "--quiet", "--force", "FETCH_HEAD", cwd=dest, timeout=timeout)
        commit = _git("rev-parse", "HEAD", cwd=dest, timeout=timeout)
    except subprocess.TimeoutExpired:
        shutil.rmtree(dest, ignore_errors=True)
        raise FetchError(f"downloading {url} took longer than {timeout}s") from None
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(dest, ignore_errors=True)
        stderr = exc.stderr or ""
        if "could not read Username" in stderr or "Authentication failed" in stderr:
            # GitHub answers a missing repo with a login prompt, in case it's private.
            hint = "repository not found, or it is private"
        elif "couldn't find remote ref" in stderr or "not our ref" in stderr:
            hint = f"no branch, tag or commit named {ref!r}"
        else:
            lines = stderr.strip().splitlines()
            hint = lines[-1] if lines else "unknown git error"
        raise FetchError(
            f"could not download {url}{f' at {ref}' if ref else ''}: {hint}\n"
            "Check the URL and ref; private repositories are not supported."
        ) from None
    except FileNotFoundError:
        raise FetchError("git is not installed") from None

    size = _size_mb(dest)
    if size > max_mb:
        shutil.rmtree(dest, ignore_errors=True)
        raise FetchError(f"{url} is {size:.0f} MB, over the {max_mb:.0f} MB limit")
    (dest / _MARKER).write_text(commit)
    return commit
