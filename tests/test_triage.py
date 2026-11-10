import pytest

from sast_triage import triage
from sast_triage.models import Candidate, Finding, Location, TraceStep


def _candidate(tmp_path, trace=()):
    (tmp_path / "db.py").write_text("".join(f"line {i}\n" for i in range(1, 41)))
    finding = Finding(
        fingerprint="f1", scanner="codeql", rule_id="py/sql-injection",
        message="This SQL query depends on a user-provided value.", severity="high",
        cwe=["CWE-89"], location=Location(file="db.py", start_line=20, end_line=21),
        snippet="line 20\nline 21", confidence="high", trace=list(trace),
    )
    return Candidate(
        id="c1", file="db.py", start_line=20, end_line=21, snippet="line 20\nline 21",
        cwe=["CWE-89"], severity="high", scanners=["codeql"], findings=[finding],
    )


def _ok(**over):
    data = dict(weakness_under_review="SQL injection (CWE-89) on line 20",
                source_is_attacker_controlled="yes", sanitized="no", reasoning="Line 20 ...",
                missing_context=None, verdict="true_positive", confidence=0.9,
                exploit_scenario="x", fix="y")
    data.update(over)
    return triage.Judgement(**data)


def test_prompt_has_context_marks_and_untrusted_tags(tmp_path):
    system, human = triage.build_messages(_candidate(tmp_path), tmp_path)
    assert system[0] == "system" and "untrusted" in system[1]
    text = human[1]
    assert ">20 | line 20" in text and ">21 | line 21" in text   # flagged lines marked
    assert " 8 | line 8" in text and " 33 | line 33" in text     # 12 lines of context each side
    assert "line 7\n" not in text and "line 34" not in text
    assert "<code>" in text and "</code>" in text
    assert "[codeql] py/sql-injection" in text and "rule confidence: high" in text
    assert text.startswith("Question: is the weakness these rules claim (CWE-89)")
    assert "Judge only that claimed weakness" in system[1]
    assert "not on what comments" in system[1]


def test_prompt_includes_trace_when_present(tmp_path):
    trace = [TraceStep(file="app.py", line=28, code='name = request.args.get("name")'),
             TraceStep(file="db.py", line=20, code="line 20")]
    _, human = triage.build_messages(_candidate(tmp_path, trace), tmp_path)
    assert "Data-flow trace reported by codeql" in human[1]
    assert 'app.py:28 | name = request.args.get("name")' in human[1]


def test_triage_candidate_uses_judge(tmp_path):
    seen = {}

    def judge(messages):
        seen["messages"] = messages
        return _ok()

    v = triage.triage_candidate(_candidate(tmp_path), tmp_path, judge, "test-model")
    assert v.verdict == "true_positive" and v.candidate_id == "c1" and v.model == "test-model"
    assert v.prompt_version == triage.PROMPT_VERSION
    assert v.error is None and len(seen["messages"]) == 2


def test_failed_call_becomes_needs_review(tmp_path):
    def broken(messages):
        raise TimeoutError("rate limited")

    v = triage.triage_candidate(_candidate(tmp_path), tmp_path, broken, "m")
    assert v.verdict == "needs_review" and v.confidence == 0.0
    assert v.error == "TimeoutError: rate limited"


def test_judgement_validates_confidence():
    with pytest.raises(ValueError):
        _ok(confidence=1.5)


def test_groq_judge_needs_a_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="GROQ_API_KEY"):
        triage.groq_judge()


def _import_candidate(rule_id="B403.blacklist", scanner="bandit"):
    f = Finding(fingerprint="i", scanner=scanner, rule_id=rule_id, message="m", severity="low",
                location=Location(file="app.py", start_line=5, end_line=5), snippet="import pickle")
    return Candidate(id="imp", file="app.py", start_line=5, end_line=5, snippet="import pickle",
                     severity="low", scanners=[scanner], findings=[f])


def test_import_warnings_are_dismissed_without_the_llm(tmp_path):
    def judge(messages):
        raise AssertionError("the LLM must not be called for import-only warnings")

    v = triage.triage_candidate(_import_candidate(), tmp_path, judge, "m")
    assert v.verdict == "false_positive" and v.model == "rule:import-warning"


def test_only_pure_import_candidates_skip_the_llm():
    assert triage.is_import_warning_only(_import_candidate("B404.blacklist"))
    assert not triage.is_import_warning_only(_import_candidate("B301.blacklist"))   # pickle.loads call
    assert not triage.is_import_warning_only(_import_candidate("B602.subprocess_popen"))
    assert not triage.is_import_warning_only(_import_candidate("B403.x", scanner="semgrep"))


def test_old_verdict_files_still_load():
    old = {"candidate_id": "c", "file": "a.py", "start_line": 1, "end_line": 1, "model": "m",
           "source_is_attacker_controlled": "yes", "sanitized": "no", "reasoning": "r",
           "verdict": "true_positive", "confidence": 0.9, "exploit_scenario": None,
           "fix": None, "error": None}
    v = triage.Verdict.model_validate(old)
    assert v.prompt_version == "v1" and v.missing_context is None


def _cand(cid, severity, scanners=("semgrep",), line=1):
    return Candidate(id=cid, file="a.py", start_line=line, end_line=line, snippet="",
                     severity=severity, scanners=list(scanners), findings=[])


def test_prioritize_orders_and_filters():
    cands = [_cand("low", "low"), _cand("hi1", "high"), _cand("crit", "critical"),
             _cand("hi3", "high", ("bandit", "codeql", "semgrep")), _cand("med", "medium")]
    assert [c.id for c in triage.prioritize(cands)] == ["crit", "hi3", "hi1", "med", "low"]
    assert [c.id for c in triage.prioritize(cands, min_severity="high")] == ["crit", "hi3", "hi1"]
    assert [c.id for c in triage.prioritize(cands, limit=2)] == ["crit", "hi3"]
