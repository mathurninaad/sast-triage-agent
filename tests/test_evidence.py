"""The evidence check, on reasoning taken from real verdicts of the demo app."""

import json
from pathlib import Path

from typer.testing import CliRunner

from sast_triage import evidence, triage
from sast_triage.cli import app
from sast_triage.context.repo import Repo
from sast_triage.models import Candidate, Citation, Finding, Location
from sast_triage.triage import Verdict

DEMO_APP = Path(__file__).parent.parent / "examples" / "demo_app"

# Agent run 1, FP-01, verbatim (note the U+2011 hyphen in "23‑24")
FP01_REASONING = (
    "The `user_id` argument of `get_user_by_id` originates from the URL path (`/users/<user_id>`) in "
    "app.py (line 34) and is immediately cast to an int (`uid = int(user_id)`) before being passed to "
    "the function (line 35). This conversion ensures only numeric values are accepted. Consequently the "
    "f‑string on lines 23‑24 of db.py receives a guaranteed integer, preventing injection of SQL syntax."
)


def cand(file="db.py", start=23, end=24) -> Candidate:
    f = Finding(fingerprint="f", scanner="semgrep", rule_id="r", message="m", severity="medium",
                location=Location(file=file, start_line=start, end_line=end), snippet="x")
    return Candidate(id="c", file=file, start_line=start, end_line=end, snippet="x",
                     severity="medium", scanners=["semgrep"], findings=[f])


def verdict(reasoning, v="false_positive", **over) -> Verdict:
    base = dict(candidate_id="c", file="db.py", start_line=23, end_line=24, model="m",
                source_is_attacker_controlled="yes", sanitized="yes", reasoning=reasoning,
                verdict=v, confidence=0.9)
    return Verdict(**(base | over))


def cites(text, default="db.py"):
    return [(c.resolved, c.start, c.end) for c in evidence.extract(text, default, evidence._Files(Repo(DEMO_APP)))]


# Extraction


def test_citation_forms_seen_in_real_verdicts():
    assert cites("taken from the query string on line 58.", "app.py") == [("app.py", 58, 58)]
    assert cites("invoked with `shell=True` on line 59‑61.", "app.py") == [("app.py", 59, 61)]
    assert cites("comes from the route (app.py lines 28‑29).") == [("app.py", 28, 29)]
    assert cites("passed to it (db.py line 13).", "app.py") == [("db.py", 13, 13)]
    assert cites("the f-string on lines 23-24 of db.py is safe.", "app.py") == [("db.py", 23, 24)]
    assert cites("see db.py:15-16 and app.py:34.", "app.py") == [("db.py", 15, 16), ("app.py", 34, 34)]


def test_bare_line_numbers_use_the_file_named_in_the_same_sentence():
    # Single-shot v3 on TP-01: app.py is named in an earlier sentence, line 15 is db.py's
    text = ('The `name` argument originates from `request.args.get("name")` in app.py. '
            "It is passed unchanged into the f-string on line 15.")
    assert cites(text) == [("db.py", 15, 15)]
    assert cites("In app.py the value is cast (line 34) before the call (line 35).") == [
        ("app.py", 34, 34), ("app.py", 35, 35)]


def test_dots_in_code_do_not_end_sentences():
    text = "It originates from `pickle.loads(request.get_data())` at line 89. Version 1.0 is constant."
    assert [text[a:b].strip() for a, b in evidence.sentences(text)] == [
        "It originates from `pickle.loads(request.get_data())` at line 89.", "Version 1.0 is constant."]


def test_unknown_file_names_do_not_capture_bare_lines():
    # "request.json" looks like a file name but is not one in the repo
    assert cites("It reads request.json and uses it on line 23.") == [("db.py", 23, 23)]


# Checking


def statuses(reasoning, seen=None, c=None):
    return [(x.file, x.start_line, x.status) for x in evidence.check(reasoning, c or cand(), Repo(DEMO_APP), seen)]


def test_real_fp01_reasoning_is_verified():
    seen = "app.py\n" + (DEMO_APP / "app.py").read_text() + "\ndb.py\n" + (DEMO_APP / "db.py").read_text()
    assert statuses(FP01_REASONING, seen) == [
        ("app.py", 34, "verified"), ("app.py", 35, "verified"), ("db.py", 23, "verified")]


def test_citing_code_the_model_never_read_is_unseen():
    seen_db_only = "db.py\n" + (DEMO_APP / "db.py").read_text()
    result = statuses(FP01_REASONING, seen_db_only)
    assert ("app.py", 34, "unseen") in result and ("db.py", 23, "verified") in result
    assert evidence.status_of(evidence.check(FP01_REASONING, cand(), Repo(DEMO_APP), seen_db_only)) == "unseen"


def test_made_up_evidence_is_contradicted():
    assert statuses("app.py (line 340) validates it.") == [("app.py", 340, "contradicted")]
    assert statuses("utils/validate.py:12 sanitises it.") == [("utils/validate.py", 12, "contradicted")]
    # a real line, but the quoted sanitizer is not there
    c = evidence.check("Line 15 escapes it with `sanitize_sql(name)`.", cand("db.py", 15, 15), Repo(DEMO_APP))
    assert c[0].status == "contradicted" and "sanitize_sql(name)" in c[0].detail


def test_quotes_without_a_line_number():
    # single-shot v3 on FP-02: found in the code, so it counts as evidence
    c = evidence.check("It is passed through `shlex.quote` before use.", cand("app.py", 70, 72), Repo(DEMO_APP))
    assert [(x.file, x.start_line, x.status) for x in c] == [("app.py", 71, "verified")]
    # not found anywhere: ignored, not contradicted (it may be a negation)
    assert evidence.check("No `html.escape(value)` is applied.", cand(), Repo(DEMO_APP)) == []


# The rule


def test_false_positive_without_verified_evidence_goes_to_review():
    v = evidence.apply(verdict("Only server-side data reaches it."), [])
    assert v.verdict == "needs_review" and v.original_verdict == "false_positive"
    assert v.evidence_status == "none" and "cites no specific line" in v.missing_context

    bad = Citation(file="app.py", start_line=340, end_line=340, status="contradicted", detail="app.py has only 122 lines")
    v = evidence.apply(verdict("x"), [bad])
    assert v.verdict == "needs_review" and "app.py:340: app.py has only 122 lines" in v.missing_context


def test_verified_false_positive_and_any_true_positive_are_unchanged():
    ok = Citation(file="db.py", start_line=23, end_line=24, status="verified")
    assert evidence.apply(verdict("x"), [ok]).verdict == "false_positive"
    v = evidence.apply(verdict("x", v="true_positive"), [])
    assert v.verdict == "true_positive" and v.original_verdict is None and v.evidence_status == "none"


def test_rule_based_and_failed_verdicts_are_not_checked():
    rule = verdict("Only an import is flagged.", model="rule:import-warning")
    assert evidence.check_verdict(rule, cand(), DEMO_APP) == rule
    failed = verdict("Automatic triage failed.", v="needs_review", error="boom")
    assert evidence.check_verdict(failed, cand(), DEMO_APP) == failed


def test_a_crash_in_the_check_never_loses_the_verdict(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("bug")
    monkeypatch.setattr(evidence, "check", boom)
    v = evidence.check_verdict(verdict("x"), cand(), DEMO_APP)
    assert v.verdict == "false_positive" and v.evidence_status == "error"


# Integration


def test_single_shot_checks_against_the_window_it_was_shown():
    def judge_saying(reasoning):
        def judge(messages):
            return triage.Judgement(weakness_under_review="w", source_is_attacker_controlled="no", sanitized="yes",
                                    reasoning=reasoning, missing_context=None, verdict="false_positive",
                                    confidence=0.9, exploit_scenario=None, fix=None)
        return judge
    c = cand("db.py", 23, 24)
    v = triage.triage_candidate(c, DEMO_APP, judge_saying("The query on lines 23-24 is fine."), "m")
    assert v.error is None
    assert v.verdict == "false_positive" and v.evidence_status == "verified"
    # app.py:34 is a real line, but single-shot was only shown db.py
    v = triage.triage_candidate(c, DEMO_APP, judge_saying("app.py (line 34) casts it with int()."), "m")
    assert v.verdict == "needs_review" and v.evidence_status == "unseen"
    v = triage.triage_candidate(c, DEMO_APP, judge_saying("app.py (line 34) casts it."), "m", evidence_check=False)
    assert v.verdict == "false_positive" and v.evidence_status is None


def test_check_evidence_command(tmp_path):
    scan = tmp_path / "scan"
    scan.mkdir()
    (scan / "candidates.json").write_text(json.dumps([cand().model_dump(mode="json")]))
    (scan / "meta.json").write_text(json.dumps({"source_root": str(DEMO_APP)}))
    (scan / "verdicts.json").write_text(json.dumps([verdict("It is safe.").model_dump(mode="json")]))
    result = CliRunner().invoke(app, ["check-evidence", str(scan), "--out", "checked.json"])
    assert result.exit_code == 0, result.output
    assert "1 false_positive verdict(s) sent to review" in result.output
    saved = json.loads((scan / "checked.json").read_text())[0]
    assert saved["verdict"] == "needs_review" and saved["original_verdict"] == "false_positive"


def test_quote_defined_elsewhere_and_used_on_the_cited_line():
    """Agent run 2, FP-02 (verbatim): the quote is the definition (line 20), the cite
    is where it is used (line 68). True claim, so it is verified, with both lines."""
    text = ("However, the code validates it against a strict whitelist regex "
            '`HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")` at line 68, which permits only '
            "alphanumeric characters, dots and hyphens.")
    c = evidence.check(text, cand("app.py", 70, 72), Repo(DEMO_APP))
    assert [(x.file, x.start_line, x.status) for x in c] == [("app.py", 68, "verified"), ("app.py", 20, "verified")]
    # still contradicted: code that exists nowhere, even if a name in it appears on the line
    c = evidence.check("Line 68 checks it with `HOSTNAME_RE.fullmatch_safe(host)`.", cand("app.py", 70, 72),
                       Repo(DEMO_APP))
    assert c[0].status == "contradicted"
    # still contradicted: real code elsewhere, but nothing in it appears on the cited line
    c = evidence.check("Line 15 converts it with `uid = int(user_id)`.", cand("db.py", 15, 15), Repo(DEMO_APP))
    assert c[0].status == "contradicted"


def test_single_shot_records_token_usage():
    def judge(messages):
        return (triage.Judgement(weakness_under_review="w", source_is_attacker_controlled="yes", sanitized="no",
                                 reasoning="Line 15 builds the query.", missing_context=None,
                                 verdict="true_positive", confidence=0.9, exploit_scenario=None, fix=None),
                {"input_tokens": 1200, "output_tokens": 150})
    v = triage.triage_candidate(cand("db.py", 15, 16), DEMO_APP, judge, "m")
    assert (v.tokens_in, v.tokens_out, v.model_calls) == (1200, 150, 1)
    assert triage.token_report([v])["total"] == 1350
