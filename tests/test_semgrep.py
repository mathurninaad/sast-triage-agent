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
    """Real semgrep run, offline: our test rule must hit both pickle loads."""
    output = sg.run_semgrep(DEMO_APP, [str(FIXTURES / "rules" / "pickle_load.yaml")])
    hits = sorted((r["path"], r["start"]["line"]) for r in output["results"])
    assert hits == [("app.py", 88), ("app.py", 105)]


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
