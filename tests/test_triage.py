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
    data = dict(source_is_attacker_controlled="yes", sanitized="no", reasoning="Line 20 ...",
                verdict="true_positive", confidence=0.9, exploit_scenario="x", fix="y")
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
