from pathlib import Path

import pytest

from sast_triage.scanners import bandit as bd

DEMO_APP = Path(__file__).parent.parent / "examples" / "demo_app"


@pytest.fixture
def sample_output():
    # Shape copied from a real Bandit 1.9 run on the demo app.
    return {
        "errors": [],
        "metrics": {"./app.py": {}, "./db.py": {}, "_totals": {}},
        "results": [
            {
                "code": "42     password_hash = hashlib.md5(password.encode()).hexdigest()\n",
                "col_offset": 20,
                "end_col_offset": 50,
                "filename": "./app.py",
                "issue_confidence": "HIGH",
                "issue_cwe": {"id": 327, "link": "https://cwe.mitre.org/data/definitions/327.html"},
                "issue_severity": "HIGH",
                "issue_text": "Use of weak MD5 hash for security. Consider usedforsecurity=False",
                "line_number": 42,
                "line_range": [42],
                "more_info": "https://bandit.readthedocs.io/en/1.9.4/plugins/b324_hashlib.html",
                "test_id": "B324",
                "test_name": "hashlib",
            },
            {
                "col_offset": 0,
                "end_col_offset": 13,
                "filename": "./app.py",
                "issue_confidence": "HIGH",
                "issue_cwe": {"id": 502},
                "issue_severity": "LOW",
                "issue_text": "Consider possible security implications associated with pickle module.",
                "line_number": 5,
                "line_range": [5],
                "test_id": "B403",
                "test_name": "blacklist",
            },
        ],
    }


def test_to_findings_maps_fields(sample_output, tmp_path):
    (tmp_path / "app.py").write_text("\n" * 41 + "    password_hash = hashlib.md5(password.encode()).hexdigest()\n")
    md5 = bd.to_findings(sample_output, tmp_path)[0]
    assert md5.scanner == "bandit"
    assert md5.rule_id == "B324.hashlib" and md5.rule_name == "hashlib"
    assert md5.location.file == "app.py"              # "./" stripped
    assert md5.location.start_col == 21               # 0-based 20 -> 1-based 21
    assert md5.cwe == ["CWE-327"]
    assert md5.severity.value == "high" and md5.confidence == "HIGH"
    assert md5.snippet.strip().startswith("password_hash = hashlib.md5")


def test_summarize(sample_output):
    s = bd.summarize(sample_output)
    assert s["results"] == 2 and s["files_scanned"] == 2
    assert s["by"]["severity"] == {"HIGH": 1, "LOW": 1}
    assert s["by"]["cwe"] == {"CWE-327": 1, "CWE-502": 1}


def test_missing_target():
    with pytest.raises(bd.BanditError):
        bd.run_bandit(Path("does/not/exist"))


def test_run_bandit_on_demo_app():
    """Real Bandit run: the same 10 hits we saw in step 2, paths relative.

    Multi-line calls start at the first line of Bandit's line_range (59, 70),
    not its headline line_number (60, 71), which matches where Semgrep starts."""
    output = bd.run_bandit(DEMO_APP)
    hits = sorted((f.location.file, f.location.start_line, f.rule_id.split(".")[0])
                  for f in bd.to_findings(output, DEMO_APP))
    assert hits == [
        ("app.py", 5, "B403"), ("app.py", 8, "B404"), ("app.py", 42, "B324"),
        ("app.py", 59, "B602"), ("app.py", 70, "B602"), ("app.py", 88, "B301"),
        ("app.py", 105, "B301"), ("app.py", 117, "B324"),
        ("db.py", 15, "B608"), ("db.py", 23, "B608"),
    ]


def test_skips_dependency_folders(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    venv = tmp_path / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "dep.py").write_text("import pickle\npickle.loads(b'')\n")
    output = bd.run_bandit(tmp_path)
    assert output["results"] == []
