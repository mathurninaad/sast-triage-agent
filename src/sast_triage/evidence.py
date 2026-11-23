"""Evidence check: are the code citations in a verdict real?

When the model dismisses a finding, it justifies itself by pointing at code
("app.py (line 34) converts it with `uid = int(user_id)`"). Those are claims
about the repository, so we check them against the repository, with plain
code and no second model:

1. extract the citations from the reasoning: "line 58", "lines 59-61",
   "app.py (line 34)", "lines 23-24 of db.py", "db.py:15". A bare line
   number belongs to the file last named in the same sentence, or else to
   the flagged file;
2. the file must exist and the line must be inside it;
3. code quoted in backticks in the same sentence must be within a few lines
   of that sentence's citations;
4. the cited line must have been in front of the model: in its tool
   results (agent) or in the code window it was shown (single-shot).

Code quoted without a line number counts as evidence when it is found in
the repository, and is ignored when it is not (it may be a negation:
"no `html.escape` is applied").

A verdict is "verified" only if every citation is verified and there is at
least one. The rule is deliberately one-sided: a false_positive that is not
verified becomes needs_review, because dropping a real bug is the costly
mistake. A true_positive is never changed. This checks that the evidence
exists, not that the reasoning about it is right.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from sast_triage.context.repo import Repo, RepoError
from sast_triage.models import Candidate, Citation

QUOTE_WINDOW = 3          # quoted code must be within this many lines of a citation
MAX_SEARCH_FILES = 2000   # cap for looking up quotes without a line number

_DASHES = str.maketrans({c: "-" for c in "‐‑‒–—−"})
_EXT = (r"py|pyi|js|jsx|mjs|cjs|ts|tsx|java|kt|scala|go|rb|php|cs|rs|c|cc|cpp|h|hpp|swift"
        r"|html?|ya?ml|json|xml|toml|ini|cfg|sql|sh")
_FILE = rf"(?:\./)?(?:[\w-]+/)*[\w-]+\.(?:{_EXT})"
FILE_RE = re.compile(rf"(?<![\w/.-])({_FILE})(?![\w-])")
LINE_RE = re.compile(r"\b[Ll]ines?\s+(\d+)(?:\s*(?:-|to)\s*(\d+))?")
COLON_RE = re.compile(r":(\d+)(?:-(\d+))?\b")
BEFORE_RE = re.compile(rf"({_FILE})\s*[(,]?\s*(?:on\s+|at\s+)?$")
AFTER_RE = re.compile(rf"^\s*(?:of|in)\s+({_FILE})")
QUOTE_RE = re.compile(r"`([^`\n]{2,160})`")
# A sentence ends at . ! or ? followed by a space and a capital, bracket or quote,
# so the dots in "pickle.loads" or "version 1.0" are not sentence ends.
SENTENCE_END_RE = re.compile(r"[.!?](?=\s+[A-Z(`\"']|\s*$)")


@dataclass
class _Raw:
    file: str | None          # as written, None if it came from context
    resolved: str | None      # repo-relative path, None if it doesn't exist
    start: int
    end: int
    pos: int


def _norm(code: str) -> str:
    """Compare code ignoring whitespace and quote style."""
    return re.sub(r"\s+", "", code).replace('"', "'")


def _code_like(quote: str) -> bool:
    return any(ch in quote for ch in "(=[.") and len(_norm(quote)) >= 4


class _Files:
    """File lookups for one check, cached."""

    def __init__(self, repo: Repo):
        self.repo, self._lines, self._all = repo, {}, None

    def all(self) -> list[str]:
        if self._all is None:
            self._all = [self.repo.rel(p) for p in self.repo.files()[:MAX_SEARCH_FILES]]
        return self._all

    def resolve(self, name: str) -> str | None:
        """Repo-relative path for a file name as the model wrote it: exact, or the
        one file that ends with it ("views.py" for "app/views.py")."""
        name = name.removeprefix("./")
        try:
            if self.repo.resolve(name).is_file():
                return name
        except RepoError:
            return None
        matches = [f for f in self.all() if f.endswith("/" + name)]
        return matches[0] if len(matches) == 1 else None

    def lines(self, rel: str) -> list[str]:
        if rel not in self._lines:
            try:
                self._lines[rel] = self.repo.read_lines(rel)
            except RepoError:
                self._lines[rel] = []
        return self._lines[rel]


def sentences(text: str) -> list[tuple[int, int]]:
    """(start, end) of each sentence."""
    spans, start = [], 0
    for m in SENTENCE_END_RE.finditer(text):
        spans.append((start, m.end()))
        start = m.end()
    if text[start:].strip():
        spans.append((start, len(text)))
    return spans


def extract(text: str, default_file: str, files: _Files) -> list[_Raw]:
    """Line citations in `text`, each with the file it refers to."""
    text = text.translate(_DASHES)
    spans = sentences(text)
    mentions = [(m.start(), m.group(1), files.resolve(m.group(1))) for m in FILE_RE.finditer(text)]
    found: list[_Raw] = []
    for m in FILE_RE.finditer(text):                        # db.py:15 or db.py:15-16
        colon = COLON_RE.match(text, m.end())
        if colon:
            start = int(colon.group(1))
            found.append(_Raw(m.group(1), files.resolve(m.group(1)), start,
                              int(colon.group(2) or start), m.start()))
    for m in LINE_RE.finditer(text):                        # line 58, lines 59-61
        start = int(m.group(1))
        end = int(m.group(2) or start)
        before = BEFORE_RE.search(text[max(0, m.start() - 60):m.start()])
        after = AFTER_RE.match(text[m.end():m.end() + 60])
        if before or after:
            name = (before or after).group(1)
            found.append(_Raw(name, files.resolve(name), start, end, m.start()))
        else:                                   # the file last named in this sentence
            lo = next((a for a, b in spans if a <= m.start() < b), 0)
            last = [rel for pos, _, rel in mentions if lo <= pos < m.start() and rel]
            rel = last[-1] if last else default_file
            found.append(_Raw(None, rel, start, end, m.start()))
    for c in found:
        c.start, c.end = min(c.start, c.end), max(c.start, c.end)
    return sorted(found, key=lambda c: c.pos)


def _seen(lines: list[str], start: int, end: int, rel: str, seen_text: str | None) -> bool:
    """Was this code in front of the model? Matched by content (the first 40
    characters of each non-trivial line), so it works for any tool's output format."""
    if seen_text is None:
        return True
    if Path(rel).name not in seen_text:
        return False
    probes = [ln.strip()[:40] for ln in lines[start - 1:end] if len(ln.strip()) >= 4]
    return not probes or any(p in seen_text for p in probes)


def _quote_near(quote: str, cites: list[_Raw], files: _Files) -> bool:
    parts = [_norm(p.removesuffix("()")) for p in quote.split("...") if p.strip()]
    for c in cites:
        lines = files.lines(c.resolved) if c.resolved else []
        window = _norm("".join(lines[max(0, c.start - 1 - QUOTE_WINDOW):c.end + QUOTE_WINDOW]))
        if parts and all(p in window for p in parts):
            return True
    return False


def _find_quote(quote: str, prefer: list[str], files: _Files, anchor: int) -> tuple[str, int] | None:
    """Where quoted code appears: in the first preferred file that has it (in the
    flagged file, the occurrence closest to the flagged line), else anywhere."""
    target = _norm(quote.removesuffix("()"))
    for i, rel in enumerate(dict.fromkeys([*prefer, *files.all()])):
        hits = [n for n, line in enumerate(files.lines(rel), 1) if target in _norm(line)]
        if hits:
            return rel, (min(hits, key=lambda n: abs(n - anchor)) if i == 0 else hits[0])
    return None


def check(reasoning: str, candidate: Candidate, repo: Repo, seen_text: str | None = None) -> list[Citation]:
    """Check every citation in `reasoning`. With seen_text=None (re-checking a saved
    verdict, whose transcript is gone) the 'was it seen' step is skipped."""
    files = _Files(repo)
    text = reasoning.translate(_DASHES)
    raws = extract(text, candidate.file, files)
    results: list[Citation] = []
    for lo, hi in sentences(text):
        sentence = text[lo:hi]
        cites = [c for c in raws if lo <= c.pos < hi]
        quotes = [q for q in QUOTE_RE.findall(sentence) if _code_like(q)]
        if cites:
            bad_quotes = [q for q in quotes if not _quote_near(q, [c for c in cites if c.resolved], files)]
            for c in cites:
                shown = c.resolved or c.file or "?"
                cite = dict(file=shown, start_line=c.start, end_line=c.end,
                            quote=", ".join(quotes) or None)
                lines = files.lines(c.resolved) if c.resolved else []
                if not c.resolved:
                    results.append(Citation(**cite, status="contradicted",
                                            detail=f"there is no file {c.file!r} in the repository"))
                elif c.start > len(lines) or c.start < 1:
                    results.append(Citation(**cite, status="contradicted",
                                            detail=f"{shown} has only {len(lines)} lines"))
                elif bad_quotes:
                    results.append(Citation(**cite, status="contradicted",
                                            detail=f"`{bad_quotes[0]}` is not within {QUOTE_WINDOW} lines of "
                                                   f"the cited lines"))
                elif not _seen(lines, c.start, min(c.end, len(lines)), c.resolved, seen_text):
                    results.append(Citation(**cite, status="unseen",
                                            detail="this line was never shown to the model"))
                else:
                    results.append(Citation(**cite, status="verified"))
        else:  # quoted code without a line number: evidence if found, ignored if not
            prefer = [candidate.file, *[r for n in FILE_RE.findall(sentence) if (r := files.resolve(n))]]
            for q in quotes:
                where = _find_quote(q, prefer, files, candidate.start_line)
                if where:
                    rel, line = where
                    seen = _seen(files.lines(rel), line, line, rel, seen_text)
                    results.append(Citation(file=rel, start_line=line, end_line=line, quote=q,
                                            status="verified" if seen else "unseen",
                                            detail="" if seen else "this line was never shown to the model"))
    return results


def status_of(citations: list[Citation]) -> str:
    if not citations:
        return "none"
    for status in ("contradicted", "unseen"):  # one bad citation is enough
        if any(c.status == status for c in citations):
            return status
    return "verified"


_EXPLAIN = {
    "none": "the reasoning cites no specific line or code",
    "unseen": "the cited lines were never shown to the model",
}


def apply(verdict, citations: list[Citation]):
    """Attach the check to a Verdict and apply the one-sided rule."""
    status = status_of(citations)
    update = {"evidence": citations, "evidence_status": status}
    if verdict.verdict == "false_positive" and status != "verified":
        first_bad = next((c for c in citations if c.status == "contradicted"), None)
        why = (f"{first_bad.file}:{first_bad.start_line}: {first_bad.detail}" if first_bad
               else _EXPLAIN[status])
        update |= {"verdict": "needs_review", "original_verdict": "false_positive",
                   "missing_context": f"Evidence check failed: {why}."}
    return verdict.model_copy(update=update)


def check_verdict(verdict, candidate: Candidate, base_dir: Path, seen_text: str | None = None):
    """check() then apply(), for one verdict. Rule-based and failed verdicts are
    left alone; a crash in the check itself never loses the verdict."""
    if verdict.error or verdict.model.startswith("rule:"):
        return verdict
    try:
        citations = check(verdict.reasoning, candidate, Repo(base_dir), seen_text)
    except Exception as exc:  # noqa: BLE001
        return verdict.model_copy(update={"evidence_status": "error",
                                          "missing_context": verdict.missing_context or f"Evidence check error: {exc}"})
    return apply(verdict, citations)
