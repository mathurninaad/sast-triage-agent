import json
from pathlib import Path

import pytest

from sast_triage.scanners import semgrep as sg

FIXTURES = Path(__file__).parent / "fixtures"
DEMO_APP = Path(__file__).parent.parent / "examples" / "demo_app"


@pytest.fixture
def sample_output():
    return json.loads((FIXTURES / "semgrep_sample.json").read_text())


def test_short_rule_id():
    assert sg.short_rule_id("python.lang.security.audit.formatted-sql-query") == "formatted-sql-query"


def test_cwe_ids_handles_list_and_string(sample_output):
    sql, _, flask_pickle = sample_output["results"]
    assert sg.cwe_ids(sql) == ["CWE-89"]
    assert sg.cwe_ids(flask_pickle) == ["CWE-502"]  # metadata.cwe is a plain string here


def test_summarize_counts(sample_output):
    summary = sg.summarize(sample_output)
    assert summary["results"] == 3
    assert summary["unique_locations"] == 2  # two rules hit app.py:88
    assert summary["by"]["subcategory"] == {"audit": 2, "vuln": 1}
    assert summary["by"]["cwe"] == {"CWE-502": 2, "CWE-89": 1}


def test_build_command_requires_a_config():
    with pytest.raises(ValueError):
        sg.build_command(".", [])


def test_run_semgrep_missing_target():
    with pytest.raises(sg.SemgrepError):
        sg.run_semgrep(Path("does/not/exist"), ["rules.yaml"])


def test_run_semgrep_on_demo_app_with_local_rule():
    """Real semgrep run, offline: our test rule must hit both pickle loads,
    and converting to Findings must give clean IDs and real snippets."""
    configs = [str(FIXTURES / "rules" / "pickle_load.yaml")]
    output = sg.run_semgrep(DEMO_APP, configs)
    hits = sorted((r["path"], r["start"]["line"]) for r in output["results"])
    assert hits == [("app.py", 88), ("app.py", 105)]

    findings = sorted(sg.to_findings(output, DEMO_APP, configs), key=lambda f: f.location.start_line)
    # Semgrep prefixed the ID with this machine's folder path; it must be gone.
    assert {f.rule_id for f in findings} == {"sast-triage-test-pickle-load"}
    assert "pickle.loads(request.get_data())" in findings[0].snippet
    assert findings[0].cwe == ["CWE-502"]


def test_security_only():
    output = {
        "results": [
            {"extra": {"metadata": {"category": "security"}}},
            {"extra": {"metadata": {"category": "maintainability"}}},
            {"extra": {"metadata": {}}},
        ],
        "version": "x",
    }
    kept, dropped = sg.security_only(output)
    # security kept, maintainability dropped, no category kept (could be a custom rule)
    assert len(kept["results"]) == 2 and dropped == 1
    assert kept["version"] == "x"            # other keys are kept
    assert len(output["results"]) == 3       # the original isn't modified


def test_clean_rule_id_strips_local_folder_prefix(tmp_path):
    rules_root = tmp_path / ".cache" / "semgrep-rules" / "16b9e6d45f10"
    (rules_root / "python").mkdir(parents=True)
    prefix = str(rules_root.resolve()).lstrip("/").replace("/", ".")
    raw = f"{prefix}.python.lang.security.audit.formatted-sql-query"
    assert sg.clean_rule_id(raw, [str(rules_root / "python")]) == "python.lang.security.audit.formatted-sql-query"


def test_clean_rule_id_leaves_registry_ids_alone():
    rid = "python.lang.security.audit.formatted-sql-query"
    assert sg.clean_rule_id(rid, ["p/python"]) == rid


def test_to_findings_from_fixture(sample_output, tmp_path):
    (tmp_path / "db.py").write_text("\n" * 15 + "    rows = conn.execute(query)\n")
    (tmp_path / "app.py").write_text("\n" * 87 + "    state = pickle.loads(request.get_data())\n")
    findings = sg.to_findings(sample_output, tmp_path, ["p/python"])
    assert len(findings) == 3
    sql = findings[0]
    assert sql.snippet == "    rows = conn.execute(query)"
    assert sql.severity.value == "medium" and sql.subcategory == "audit" and sql.confidence == "LOW"
    assert findings[2].severity.value == "high"  # ERROR -> high
    # two different rules on the same line get different fingerprints
    assert findings[1].fingerprint != findings[2].fingerprint


def test_to_findings_identical_lines_get_distinct_fingerprints(tmp_path):
    (tmp_path / "a.py").write_text("x = pickle.loads(d)\nx = pickle.loads(d)\n")
    def res(line):
        return {"check_id": "r", "path": "a.py", "start": {"line": line, "col": 1},
                "end": {"line": line, "col": 5}, "extra": {"message": "m", "severity": "WARNING", "metadata": {}}}
    findings = sg.to_findings({"results": [res(1), res(2)]}, tmp_path, [])
    assert findings[0].fingerprint != findings[1].fingerprint
    assert findings[1].fingerprint.endswith("-2")


def test_to_findings_missing_file_gives_empty_snippet(sample_output, tmp_path):
    findings = sg.to_findings(sample_output, tmp_path, [])
    assert all(f.snippet == "" for f in findings)
