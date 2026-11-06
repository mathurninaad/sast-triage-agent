from sast_triage import rules


def test_rule_dirs_for_maps_and_skips_missing(tmp_path):
    for name in ("python", "javascript", "typescript", "html"):
        (tmp_path / name).mkdir()
    dirs = rules.rule_dirs_for(["python", "typescript", "html", "cobol"], tmp_path)
    # typescript also pulls in javascript rules; cobol has no folder, so it's skipped
    assert [d.name for d in dirs] == ["python", "typescript", "javascript", "html"]


def test_rule_dirs_for_no_duplicates(tmp_path):
    for name in ("typescript", "javascript"):
        (tmp_path / name).mkdir()
    dirs = rules.rule_dirs_for(["javascript", "typescript"], tmp_path)
    assert [d.name for d in dirs] == ["javascript", "typescript"]


def test_cache_dir_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("SAST_TRIAGE_CACHE", str(tmp_path))
    assert rules.default_cache_dir() == tmp_path


def test_ensure_rules_reuses_complete_download(tmp_path):
    dest = tmp_path / "semgrep-rules" / rules.RULES_COMMIT[:12]
    dest.mkdir(parents=True)
    (dest / ".sast-triage-complete").touch()
    # No network needed: a completed download is returned as-is.
    assert rules.ensure_rules(cache_dir=tmp_path) == dest
