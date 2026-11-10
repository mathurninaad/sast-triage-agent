from pathlib import Path

import pytest

from sast_triage.models import Severity
from sast_triage.scanners import codeql as cq

DEMO_APP = Path(__file__).parent.parent / "examples" / "demo_app"


def _loc(file, line, msg=None):
    loc = {"physicalLocation": {"artifactLocation": {"uri": file}, "region": {"startLine": line}}}
    if msg:
        loc["message"] = {"text": msg}
    return {"location": loc}


@pytest.fixture
def sarif():
    """Minimal SARIF in CodeQL's shape: rules in an extension, one result with a code flow."""
    return {
        "runs": [{
            "tool": {
                "driver": {"name": "CodeQL", "rules": []},
                "extensions": [{
                    "name": "codeql/python-queries",
                    "rules": [{
                        "id": "py/sql-injection",
                        "helpUri": "https://codeql.github.com/codeql-query-help/python/py-sql-injection/",
                        "properties": {
                            "tags": ["security", "external/cwe/cwe-089"],
                            "precision": "high",
                            "security-severity": "8.8",
                        },
                    }],
                }],
            },
            "results": [{
                "ruleId": "py/sql-injection",
                "level": "error",
                "message": {"text": "This SQL query depends on a [user-provided value](1)."},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "db.py"},
                    "region": {"startLine": 3, "startColumn": 12, "endColumn": 31},
                }}],
                "codeFlows": [{"threadFlows": [{"locations": [
                    _loc("app.py", 2, "ControlFlowNode for request"),
                    _loc("app.py", 2, "ControlFlowNode for Attribute"),  # same line: dropped
                    _loc("app.py", 3, "ControlFlowNode for name"),
                    _loc("db.py", 1, "ControlFlowNode for name"),
                    _loc("db.py", 3, "ControlFlowNode for query"),
                ]}]}],
            }],
        }]
    }


@pytest.fixture
def code(tmp_path):
    (tmp_path / "app.py").write_text(
        "import db\nname = request.args.get('name')\ndb.find(name)\n"
    )
    (tmp_path / "db.py").write_text(
        "def find(name):\n    query = f'SELECT {name}'\n    return conn.execute(query)\n"
    )
    return tmp_path


def test_to_findings(sarif, code):
    [f] = cq.to_findings(sarif, code)
    assert f.scanner == "codeql" and f.rule_id == "py/sql-injection"
    assert f.cwe == ["CWE-89"]                     # "cwe-089" -> "CWE-89"
    assert f.severity is Severity.HIGH             # security-severity 8.8
    assert f.confidence == "high"
    assert f.message == "This SQL query depends on a user-provided value."
    assert f.snippet == "    return conn.execute(query)"
    assert f.location.start_col == 12


def test_trace_crosses_files_and_drops_repeats(sarif, code):
    [f] = cq.to_findings(sarif, code)
    assert [(s.file, s.line) for s in f.trace] == [
        ("app.py", 2), ("app.py", 3), ("db.py", 1), ("db.py", 3)
    ]
    assert f.trace[0].code == "name = request.args.get('name')"
    assert f.trace[0].note == "request"  # "ControlFlowNode for " stripped


@pytest.mark.parametrize("score, expected", [
    ("9.8", Severity.CRITICAL), ("7.5", Severity.HIGH), ("5.0", Severity.MEDIUM), ("2.0", Severity.LOW),
])
def test_severity_from_score(score, expected):
    assert cq._severity({"properties": {"security-severity": score}}, None) is expected


def test_severity_falls_back_to_level():
    assert cq._severity({}, "error") is Severity.HIGH
    assert cq._severity({}, "note") is Severity.LOW


def test_plan_languages():
    run, skipped = cq.plan_languages(["python", "typescript", "javascript", "html", "go"])
    assert run == ["python", "javascript"]   # TS and JS share one CodeQL language
    assert skipped == ["go"]                 # needs a build: not supported


def test_executable_env_override(monkeypatch, tmp_path):
    fake = tmp_path / "codeql"
    fake.write_text("")
    monkeypatch.setenv("SAST_TRIAGE_CODEQL", str(fake))
    assert cq.codeql_executable() == str(fake)
    monkeypatch.setenv("SAST_TRIAGE_CODEQL", str(tmp_path / "missing"))
    assert cq.codeql_executable() is None


@pytest.mark.skipif(cq.codeql_executable() is None, reason="CodeQL not installed")
def test_real_codeql_on_demo_app(tmp_path):
    """The two things only CodeQL found: the path traversal, and a cross-file SQL trace."""
    sarifs = cq.run_codeql(DEMO_APP, ["python"], tmp_path)
    findings = cq.to_findings(sarifs["python"], DEMO_APP)
    by_rule = {(f.rule_id, f.location.file, f.location.start_line): f for f in findings}
    assert ("py/path-injection", "app.py", 82) in by_rule
    sql = by_rule[("py/sql-injection", "db.py", 16)]
    assert sql.trace[0].file == "app.py" and sql.trace[-1].file == "db.py"
