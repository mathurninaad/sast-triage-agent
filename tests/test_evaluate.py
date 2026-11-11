from sast_triage import evaluate
from sast_triage.models import Candidate
from sast_triage.triage import Verdict

LABELS = [
    {"id": "TP-1", "verdict": "true_positive", "file": "a.py", "lines": [10, 10]},
    {"id": "TP-2", "verdict": "true_positive", "file": "a.py", "lines": [20, 21]},
    {"id": "TP-3", "verdict": "true_positive", "file": "a.py", "lines": [90, 90]},  # no scanner found it
    {"id": "FP-1", "verdict": "false_positive", "file": "a.py", "lines": [30, 30]},
    {"id": "FP-2", "verdict": "false_positive", "file": "a.py", "lines": [40, 40]},
    {"id": "FP-3", "verdict": "false_positive", "file": "a.py", "lines": [99, 99]},  # never reported: fine
]


def C(cid, start, end=None):
    return Candidate(id=cid, file="a.py", start_line=start, end_line=end or start, snippet="",
                     severity="high", scanners=["semgrep"], findings=[])


def V(cid, verdict):
    return Verdict(candidate_id=cid, file="a.py", start_line=1, end_line=1, model="m",
                   source_is_attacker_controlled="unclear", sanitized="unclear",
                   reasoning="r", verdict=verdict, confidence=0.5)


CANDS = [C("c1", 10), C("c2", 21, 22), C("c3", 30), C("c4", 40), C("c5", 60)]


def test_matching_by_overlap():
    assert evaluate.match_label(C("x", 21, 22), LABELS)["id"] == "TP-2"
    assert evaluate.match_label(C("x", 60), LABELS) is None


def test_baseline_keeps_everything():
    r = evaluate.evaluate(CANDS, [], LABELS)
    b = r["baseline"]
    assert b["candidates_kept"] == 5
    assert (b["real_kept"], b["real_candidates"]) == (2, 2)
    assert b["recall_end_to_end"] == round(2 / 3, 3)   # TP-3 never reached triage
    assert b["false_alarms_removed"] == 0.0
    assert b["precision"] == 0.5                        # 2 real of 4 labelled kept
    assert r["missed_by_scanners"] == ["TP-3"] and r["unlabelled"] == 1


def test_triage_scores():
    verdicts = [V("c1", "true_positive"), V("c2", "false_positive"),   # TP-2 wrongly dismissed
                V("c3", "false_positive"), V("c4", "needs_review"), V("c5", "false_positive")]
    r = evaluate.evaluate(CANDS, verdicts, LABELS)
    t = r["triage"]
    assert (t["real_kept"], t["real_candidates"]) == (1, 2)
    assert t["false_alarms_removed"] == 0.5     # FP-1 dismissed, FP-2 kept for review
    assert t["precision"] == 0.5                # kept & labelled: c1 (real), c4 (false)
    assert r["needs_review"] == 1
    correct = {row.candidate.id: row.correct for row in r["rows"]}
    assert correct == {"c1": True, "c2": False, "c3": True, "c4": None, "c5": None}
