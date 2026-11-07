"""The common data model every scanner's output is converted into.

Later stages (dedupe, the triage agent, reports) only ever see these
models, never a scanner's raw format, so adding a scanner never changes
them.
"""

from __future__ import annotations

import hashlib
import re
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Location(BaseModel):
    file: str = Field(description="Path relative to the scanned folder")
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    start_col: int | None = None
    end_col: int | None = None


class Finding(BaseModel):
    """One suspicious location reported by one scanner rule."""

    fingerprint: str = Field(description="Stable ID: same code + same rule = same fingerprint")
    scanner: str
    rule_id: str
    message: str
    severity: Severity
    cwe: list[str] = Field(default_factory=list, description="Bare ids, e.g. 'CWE-89'")
    location: Location
    snippet: str = Field(description="The flagged lines, read from the file")

    # The rule author's own hints. They describe the rule, not this code.
    category: str | None = None
    subcategory: str | None = None    # "vuln" = specific, "audit" = broad
    confidence: str | None = None
    likelihood: str | None = None
    impact: str | None = None
    owasp: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

    @property
    def rule_name(self) -> str:
        """'python.lang.security.audit.formatted-sql-query' -> 'formatted-sql-query'."""
        return self.rule_id.rsplit(".", 1)[-1]


_WS = re.compile(r"\s+")


def fingerprint(scanner: str, rule_id: str, file: str, snippet: str) -> str:
    """Hash of what was flagged and where, deliberately without line numbers.

    Adding code above a finding moves its line numbers but not its
    fingerprint, so a verdict cached for it stays valid. Whitespace is
    collapsed so re-indenting doesn't change it either.
    """
    normalized = _WS.sub(" ", snippet).strip()
    data = "\x1f".join((scanner, rule_id, file, normalized))
    return hashlib.sha256(data.encode()).hexdigest()[:16]
