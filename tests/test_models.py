import pytest
from pydantic import ValidationError

from sast_triage.models import Finding, Location, Severity, fingerprint


def test_fingerprint_ignores_line_numbers_and_whitespace():
    a = fingerprint("semgrep", "rule", "app.py", "x = run(cmd)")
    b = fingerprint("semgrep", "rule", "app.py", "    x  =  run(cmd)   ")
    assert a == b and len(a) == 16


def test_fingerprint_changes_with_rule_file_or_code():
    base = fingerprint("semgrep", "rule", "app.py", "x = run(cmd)")
    assert fingerprint("semgrep", "other", "app.py", "x = run(cmd)") != base
    assert fingerprint("semgrep", "rule", "db.py", "x = run(cmd)") != base
    assert fingerprint("semgrep", "rule", "app.py", "x = run(safe)") != base
    assert fingerprint("bandit", "rule", "app.py", "x = run(cmd)") != base


def _finding(**over):
    data = dict(
        fingerprint="abc",
        scanner="semgrep",
        rule_id="python.lang.security.audit.formatted-sql-query",
        message="m",
        severity="medium",
        location=Location(file="db.py", start_line=16, end_line=16),
        snippet="rows = conn.execute(query)",
    )
    data.update(over)
    return Finding(**data)


def test_finding_basics():
    f = _finding()
    assert f.severity is Severity.MEDIUM
    assert f.rule_name == "formatted-sql-query"
    assert f.cwe == [] and f.subcategory is None


def test_finding_rejects_bad_values():
    with pytest.raises(ValidationError):
        _finding(severity="urgent")
    with pytest.raises(ValidationError):
        Location(file="a.py", start_line=0, end_line=1)


def test_finding_round_trips_through_json():
    f = _finding(cwe=["CWE-89"])
    again = Finding.model_validate_json(f.model_dump_json())
    assert again == f
