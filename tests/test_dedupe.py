from sast_triage.dedupe import group_findings
from sast_triage.models import Finding, Location, Severity, max_severity


def F(line, end=None, cwe=("CWE-89",), scanner="semgrep", rule="r", file="app.py", sev="medium"):
    return Finding(
        fingerprint=f"{scanner}-{rule}-{file}-{line}",
        scanner=scanner, rule_id=rule, message="m", severity=sev, cwe=list(cwe),
        location=Location(file=file, start_line=line, end_line=end or line), snippet="x",
    )


def groups(findings, tmp_path):
    return [(c.start_line, c.end_line, len(c.findings)) for c in group_findings(findings, tmp_path)]


def test_overlapping_lines_merge_across_scanners(tmp_path):
    # Semgrep flags 59 and 60, Bandit flags 59-61: one multi-line call
    fs = [F(59, cwe=["CWE-78"]), F(60, cwe=["CWE-78"]), F(59, 61, cwe=["CWE-78"], scanner="bandit")]
    cands = group_findings(fs, tmp_path)
    assert len(cands) == 1
    assert (cands[0].start_line, cands[0].end_line) == (59, 61)
    assert cands[0].scanners == ["bandit", "semgrep"]


def test_adjacent_lines_merge_only_with_shared_cwe(tmp_path):
    # SQL built on 15 (Bandit), run on 16 (Semgrep): same bug
    assert groups([F(15, scanner="bandit"), F(16)], tmp_path) == [(15, 16, 2)]
    # imports on 5 and 8 with different CWEs: separate
    assert len(groups([F(5, cwe=["CWE-502"]), F(8, cwe=["CWE-78"])], tmp_path)) == 2
    # adjacent but different CWEs: separate
    assert len(groups([F(15, cwe=["CWE-89"]), F(16, cwe=["CWE-79"])], tmp_path)) == 2


def test_far_apart_same_cwe_stays_separate(tmp_path):
    # pickle.dump on 98 and pickle.load on 105
    assert len(groups([F(98, cwe=["CWE-502"]), F(105, cwe=["CWE-502"])], tmp_path)) == 2


def test_same_line_different_cwe_merges(tmp_path):
    # e.g. template injection flagged as CWE-79 by one rule and CWE-96 by another
    cands = group_findings([F(50, cwe=["CWE-79"]), F(50, cwe=["CWE-96"])], tmp_path)
    assert len(cands) == 1 and cands[0].cwe == ["CWE-79", "CWE-96"]


def test_files_kept_apart_and_sorted(tmp_path):
    cands = group_findings([F(16, file="db.py"), F(16, file="app.py")], tmp_path)
    assert [c.file for c in cands] == ["app.py", "db.py"]


def test_severity_is_the_maximum(tmp_path):
    cands = group_findings([F(88, sev="medium"), F(88, sev="high", scanner="bandit")], tmp_path)
    assert cands[0].severity is Severity.HIGH
    assert max_severity([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) is Severity.CRITICAL


def test_snippet_covers_the_whole_group(tmp_path):
    (tmp_path / "app.py").write_text("".join(f"line {i}\n" for i in range(1, 21)))
    cands = group_findings([F(10), F(11, 12)], tmp_path)
    assert cands[0].snippet == "line 10\nline 11\nline 12"


def test_candidate_id_is_stable(tmp_path):
    a = group_findings([F(1), F(1, scanner="bandit")], tmp_path)[0].id
    b = group_findings([F(1, scanner="bandit"), F(1)], tmp_path)[0].id
    assert a == b
