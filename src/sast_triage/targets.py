"""Turn what the user typed (a folder or a GitHub URL) into a local folder.

Everything downstream (language detection, scanners, later the agent's
tools) only ever sees a local folder.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from sast_triage import fetch
from sast_triage.rules import default_cache_dir

# https://github.com/<owner>/<repo>, optionally ending in ".git" or "/".
_GITHUB_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)


class TargetError(RuntimeError):
    """The target is not a usable folder or GitHub URL."""


@dataclass(frozen=True)
class Target:
    path: Path                 # local folder (or file) to scan
    source: str                # what the user typed
    commit: str | None = None  # set for GitHub targets

    @property
    def name(self) -> str:
        return self.path.resolve().name


def parse_github_url(text: str) -> tuple[str, str] | None:
    """Return (owner, repo) for a GitHub repo URL, else None."""
    m = _GITHUB_RE.match(text.strip())
    if not m:
        return None
    owner, repo = m.group("owner"), m.group("repo")
    # "." and ".." would point outside the cache folder; GitHub doesn't allow them anyway.
    if {owner, repo} & {".", ".."}:
        return None
    return owner, repo


def resolve_target(text: str, ref: str | None = None, cache_dir: Path | None = None) -> Target:
    """Resolve a folder path or GitHub URL into a local Target."""
    if parsed := parse_github_url(text):
        owner, repo = parsed
        dest = (cache_dir or default_cache_dir()) / "repos" / owner / repo
        try:
            commit = fetch.fetch_commit(f"https://github.com/{owner}/{repo}.git", dest, ref=ref)
        except fetch.FetchError as exc:
            raise TargetError(str(exc)) from None
        return Target(path=dest, source=f"{owner}/{repo}", commit=commit)

    if text.startswith(("http://", "https://", "git@")):
        raise TargetError(
            f"unsupported URL: {text}\nOnly public GitHub repos are supported, "
            "like https://github.com/owner/repo"
        )
    if ref:
        raise TargetError("--ref only applies to GitHub URLs")
    path = Path(text)
    if not path.exists():
        raise TargetError(f"target does not exist: {text}")
    return Target(path=path, source=text)
