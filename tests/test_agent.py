"""The LangGraph agent, driven by a scripted model (no API calls) and the real
code tools from our MCP server, connected in memory."""

from pathlib import Path

import anyio
from langchain_core.messages import AIMessage
from langchain_mcp_adapters.tools import load_mcp_tools
from mcp.shared.memory import create_connected_server_and_client_session

from sast_triage import agent
from sast_triage.mcp_server import build_server
from sast_triage.models import Candidate, Finding, Location
from sast_triage.triage import Judgement

DEMO_APP = Path(__file__).parent.parent / "examples" / "demo_app"


def fp01() -> Candidate:
    f = Finding(fingerprint="f", scanner="semgrep", rule_id="python.lang.security.audit.formatted-sql-query",
                message="Detected possible formatted SQL query.", severity="medium", cwe=["CWE-89"],
                location=Location(file="db.py", start_line=23, end_line=24),
                snippet='    query = f"SELECT id, username FROM users WHERE id = {user_id}"')
    return Candidate(id="fp01", file="db.py", start_line=23, end_line=24, snippet=f.snippet,
                     cwe=["CWE-89"], severity="medium", scanners=["semgrep"], findings=[f])


def call(name, args, cid):
    return {"name": name, "args": args, "id": cid}


class Script:
    """A stand-in LLM: returns pre-written messages in order and records its inputs."""
    def __init__(self, *replies):
        self.replies, self.inputs = list(replies), []

    async def __call__(self, messages):
        self.inputs.append(list(messages))
        reply = self.replies.pop(0) if self.replies else AIMessage(content="done")
        if isinstance(reply, BaseException):
            raise reply
        return reply


class ParseError(Exception):
    """Shaped like the Groq 400 from the first real run: the provider could not
    parse the model's reply, and returns what the model wrote."""
    def __init__(self, generated="We need to see where save_stats is called.", code="output_parse_failed"):
        super().__init__(f"Error code: 400 - {code}")
        self.body = {"error": {"code": code, "failed_generation": generated}}


class Decider:
    def __init__(self, verdict="false_positive", fail=False, parse_failures=0,
                 reasoning="The query at db.py lines 23-24 only ever receives an integer."):
        self.verdict, self.fail, self.seen, self.reasoning = verdict, fail, None, reasoning
        self.parse_failures, self.calls = parse_failures, 0

    async def __call__(self, messages):
        self.seen, self.calls = messages, self.calls + 1
        if self.fail:
            raise TimeoutError("rate limited")
        if self.calls <= self.parse_failures:
            raise ParseError(code="tool_use_failed")
        return Judgement(weakness_under_review="SQL injection (CWE-89), db.py 23-24",
                         source_is_attacker_controlled="yes", sanitized="yes",
                         reasoning=self.reasoning, missing_context=None,
                         verdict=self.verdict, confidence=0.9, exploit_scenario=None, fix=None)


def run(check):
    async def main():
        server = build_server(DEMO_APP)
        async with create_connected_server_and_client_session(server._mcp_server) as session:
            await check(await load_mcp_tools(session))
    anyio.run(main)


def test_graph_shape():
    graph = agent.build_graph(Script(), [], Decider())
    assert set(graph.get_graph().nodes) == {"__start__", "prepare", "agent", "tools", "finalize", "__end__"}


def test_fp01_investigation_end_to_end():
    """The agent asks who calls get_user_by_id, then reads that caller, and the final
    decision is made with the int() conversion from app.py in front of it."""
    async def check(tools):
        model = Script(
            AIMessage(content="", tool_calls=[call("find_references", {"name": "get_user_by_id"}, "1")]),
            AIMessage(content="", tool_calls=[call("get_function", {"name": "get_user"}, "2")]),
            AIMessage(content="The only caller converts user_id with int() first."),
        )
        decider = Decider()
        graph = agent.build_graph(model, tools, decider)
        v = await agent.triage_candidate(graph, fp01(), DEMO_APP, "test-model", 8)

        assert v.verdict == "false_positive" and v.prompt_version == agent.AGENT_PROMPT_VERSION
        assert v.tool_calls == ["find_references(name='get_user_by_id')", "get_function(name='get_user')"]
        log = decider.seen[-1].content
        assert "app.py:35 [call] in get_user" in log           # real tool output, via MCP
        assert "uid = int(user_id)" in log
        assert "The only caller converts" in log               # the model's own notes
        assert "Judge only that claimed weakness" in decider.seen[0].content  # same base prompt as M2
        assert "at most 8 tool calls" in model.inputs[0][0].content          # agent guidance + budget
        assert "[calls left: 7 of 8]" in log and "[calls left: 6 of 8]" in log
        assert v.tool_budget == 8 and v.budget_extended is False
    run(check)


def test_budget_is_enforced_by_code():
    """A model that never stops asking gets exactly `budget` calls, then must decide."""
    async def check(tools):
        endless = Script(*[AIMessage(content="", tool_calls=[call("list_files", {}, str(i))]) for i in range(20)])
        decider = Decider()
        graph = agent.build_graph(endless, tools, decider)
        v = await agent.triage_candidate(graph, fp01(), DEMO_APP, "m", 3)
        assert len(v.tool_calls) == 3                 # the 4th request is never run
        assert len(endless.inputs) == 4              # asked 4 times, 3 calls executed
        assert "not run: the budget of 3 was used up" in decider.seen[-1].content
    run(check)


def test_bad_and_unknown_tool_calls_become_messages():
    async def check(tools):
        model = Script(
            AIMessage(content="", tool_calls=[call("read_file", {"path": "../../etc/passwd"}, "1"),
                                              call("delete_everything", {}, "2")]),
            AIMessage(content="ok"),
        )
        decider = Decider()
        v = await agent.triage_candidate(agent.build_graph(model, tools, decider), fp01(), DEMO_APP, "m", 8)
        log = decider.seen[-1].content
        assert "outside the repository" in log
        assert "no tool called 'delete_everything'" in log
        assert v.error is None   # the run carried on
    run(check)


def test_import_warning_skips_the_model():
    f = Finding(fingerprint="i", scanner="bandit", rule_id="B403.blacklist", message="m", severity="low",
                location=Location(file="app.py", start_line=5, end_line=5), snippet="import pickle")
    cand = Candidate(id="imp", file="app.py", start_line=5, end_line=5, snippet="import pickle",
                     severity="low", scanners=["bandit"], findings=[f])
    model = Script()

    async def main():
        v = await agent.triage_candidate(agent.build_graph(model, [], Decider()), cand, DEMO_APP, "m", 8)
        assert v.verdict == "false_positive" and model.inputs == []
        assert v.prompt_version == agent.AGENT_PROMPT_VERSION
    anyio.run(main)


def test_failure_keeps_candidate_for_review():
    async def check(tools):
        graph = agent.build_graph(Script(AIMessage(content="done")), tools, Decider(fail=True))
        v = await agent.triage_candidate(graph, fp01(), DEMO_APP, "m", 8)
        assert v.verdict == "needs_review" and "rate limited" in v.error
    run(check)


def test_real_run_needs_a_key(monkeypatch):
    import pytest
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="GROQ_API_KEY"):
        anyio.run(agent.triage_all, [], DEMO_APP)


# Adaptive budget and extension


def _with(severity="medium", trace_files=()):
    from sast_triage.models import Severity, TraceStep
    c = fp01()
    trace = [TraceStep(file=f, line=1) for f in trace_files]
    f = c.findings[0].model_copy(update={"trace": trace})
    return c.model_copy(update={"severity": Severity(severity), "findings": [f]})


def test_budget_for_adapts_to_the_candidate():
    assert agent.budget_for(_with("medium")) == 8
    assert agent.budget_for(_with("critical")) == 10                             # severe: +2
    assert agent.budget_for(_with("low")) == 6                                   # low: -2
    assert agent.budget_for(_with("high", ["app.py", "db.py"])) == 14            # +2, and +4 cross-file
    assert agent.budget_for(_with("medium", ["db.py", "db.py"])) == 8            # same file: no bonus
    assert agent.budget_for(_with("critical", ["a.py", "b.py"]), base=14) == 16  # capped at the ceiling
    assert agent.budget_for(_with("low"), base=1) == 2                           # never below 2


def test_extension_is_granted_once_and_logged():
    async def check(tools):
        model = Script(
            AIMessage(content="", tool_calls=[call("list_files", {}, "1"), call("list_files", {}, "2")]),
            AIMessage(content="", tool_calls=[call("request_more_budget", {"reason": "still following callers"}, "3")]),
            AIMessage(content="", tool_calls=[call("find_references", {"name": "get_user_by_id"}, "4")]),
            AIMessage(content="", tool_calls=[call("request_more_budget", {"reason": "again"}, "5")]),
            AIMessage(content="done"),
        )
        decider = Decider()
        graph = agent.build_graph(model, tools, decider, max_budget=16, extension=4)
        v = await agent.triage_candidate(graph, fp01(), DEMO_APP, "m", 2)
        log = decider.seen[-1].content
        assert "Granted: your budget is now 6" in log
        # a second request goes straight to finalize, with a note saying why
        assert "another budget extension was requested and refused" in log
        assert len(model.inputs) == 4
        assert v.tool_budget == 6 and v.budget_extended is True
        assert "request_more_budget(reason='still following callers')" in v.tool_calls  # auditable reason
        assert "find_references(name='get_user_by_id')" in v.tool_calls                  # ran thanks to it
    run(check)


def test_extension_never_exceeds_the_ceiling():
    async def check(tools):
        model = Script(AIMessage(content="", tool_calls=[call("request_more_budget", {"reason": "r"}, "1")]),
                       AIMessage(content="done"))
        decider = Decider()
        graph = agent.build_graph(model, tools, decider, max_budget=10, extension=4)
        v = await agent.triage_candidate(graph, fp01(), DEMO_APP, "m", 8, max_budget=10)
        assert v.tool_budget == 10   # 8 + 4 would be 12; capped at 10
    run(check)


def test_repeated_extension_requests_cannot_loop():
    async def check(tools):
        nagging = Script(*[AIMessage(content="", tool_calls=[call("request_more_budget", {"reason": "r"}, str(i))])
                           for i in range(30)])
        decider = Decider()
        v = await agent.triage_candidate(agent.build_graph(nagging, tools, decider), fp01(), DEMO_APP, "m", 4)
        assert v.error is None and v.verdict == "false_positive"
        assert len(nagging.inputs) == 2   # granted once; asking again goes straight to finalize
    run(check)


def test_budget_report():
    from sast_triage.triage import Verdict
    def V(calls, budget, extended=False):
        return Verdict(candidate_id="c", file="a.py", start_line=1, end_line=1, model="m",
                       prompt_version=agent.AGENT_PROMPT_VERSION, source_is_attacker_controlled="yes",
                       sanitized="no", reasoning="r", verdict="true_positive", confidence=0.9,
                       tool_calls=calls, tool_budget=budget, budget_extended=extended)
    r = agent.budget_report([V(["a()", "b()"], 8), V(["a()"] * 8, 8),
                             V(["a()"] * 9 + ["request_more_budget(reason='x')"], 12, True)])
    assert r == {"candidates": 3, "median_calls": 8, "max_calls": 9, "hit_budget": 1, "extended": 1,
                 "parse_retries": 0, "repaired_calls": 0}


def test_prompts_have_no_stray_backslashes():
    """Regression: line continuations were once written with two backslashes,
    leaving literal '\\' characters in the agent's prompts."""
    from sast_triage import triage
    for text in (agent.AGENT_GUIDANCE, agent.FINAL_INSTRUCTION, triage.SYSTEM_PROMPT,
                 agent.RETRY_NUDGE, agent.DECIDE_NUDGE):
        assert "\\" not in text


# Hardening, from the failures of the first real run (verdicts-agent.json, agent-v1)


def test_parse_failure_is_recognised():
    assert agent.parse_failure(ParseError("plan")) == "plan"
    assert agent.parse_failure(ParseError("x", code="tool_use_failed")) == "x"
    assert agent.parse_failure(Exception("400 output_parse_failed")) == ""   # no body: still recognised
    assert agent.parse_failure(TimeoutError("rate limited")) is None          # other errors are not retried here


def test_unparseable_reply_is_retried_with_its_text_kept():
    """Run 1 lost FP-03 this way: the model wrote its plan instead of a tool call."""
    async def check(tools):
        model = Script(
            ParseError("We need to see where save_stats is called."),
            AIMessage(content="", tool_calls=[call("find_references", {"name": "save_stats"}, "1")]),
            AIMessage(content="Only called with server-side stats."),
        )
        decider = Decider()
        v = await agent.triage_candidate(agent.build_graph(model, tools, decider), fp01(), DEMO_APP, "m", 8)
        assert v.error is None and v.verdict == "false_positive"
        assert v.parse_retries == 1
        assert v.tool_calls == ["find_references(name='save_stats')"]
        retry_input = model.inputs[1]
        assert retry_input[-2].content == "We need to see where save_stats is called."  # its plan, kept
        assert retry_input[-1].content == agent.RETRY_NUDGE
        assert "We need to see where save_stats is called." in decider.seen[-1].content
    run(check)


def test_repeated_parse_failures_decide_with_what_was_found():
    """Instead of crashing to needs_review with an error, the agent stops investigating
    and the decision is still made, told that the investigation ended early."""
    async def check(tools):
        model = Script(
            AIMessage(content="", tool_calls=[call("get_function", {"name": "get_user"}, "1")]),
            *[ParseError("Need HOSTNAME_RE.") for _ in range(10)],
        )
        decider = Decider()
        graph = agent.build_graph(model, tools, decider, parse_retries=2)
        v = await agent.triage_candidate(graph, fp01(), DEMO_APP, "m", 8)
        assert v.error is None and v.verdict == "false_positive"
        assert v.parse_retries == 3 and len(model.inputs) == 4   # 1 good turn, then 1 try + 2 retries
        log = decider.seen[-1].content
        assert "stopped early" in log and "uid = int(user_id)" in log   # evidence from before the failures
    run(check)


def test_other_model_errors_still_keep_the_candidate_for_review():
    async def check(tools):
        model = Script(TimeoutError("rate limited"))
        v = await agent.triage_candidate(agent.build_graph(model, tools, Decider()), fp01(), DEMO_APP, "m", 8)
        assert v.verdict == "needs_review" and "rate limited" in v.error and len(model.inputs) == 1
    run(check)


def test_final_decision_is_retried_on_parse_failure():
    async def check(tools):
        decider = Decider(parse_failures=1)
        graph = agent.build_graph(Script(AIMessage(content="done")), tools, decider)
        v = await agent.triage_candidate(graph, fp01(), DEMO_APP, "m", 8)
        assert v.error is None and decider.calls == 2
        assert decider.seen[-1].content == agent.DECIDE_NUDGE
    run(check)


def test_repair_call():
    async def check(tools):
        by_name = {t.name: t for t in tools}
        # the exact calls from run 1
        assert agent.repair_call("repo_browser.search_code",
                                 {"max_results": 20, "path": "", "query": "get_user_by_id("}, by_name) == (
            "search_code", {"limit": 20, "query": "get_user_by_id("}, None)
        assert agent.repair_call("read_file", {"line_end": 60, "line_start": 1, "path": "app.py"}, by_name) == (
            "read_file", {"end": 60, "start": 1, "path": "app.py"}, None)
        assert agent.repair_call("search_code", {"max_results": 20, "path": "*", "query": "UPLOAD_DIR"},
                                 by_name) == ("search_code", {"limit": 20, "pattern": "*", "query": "UPLOAD_DIR"}, None)
        # correct calls are untouched; a real parameter is never overwritten by an alias
        assert agent.repair_call("get_function", {"name": "x", "file": "db.py"}, by_name) == (
            "get_function", {"name": "x", "file": "db.py"}, None)
        # unknown arguments are an error naming the real ones, not silently dropped
        name, _, error = agent.repair_call("read_file", {"path": "app.py", "lines": "80-84"}, by_name)
        assert name == "read_file" and "no parameter 'lines'" in error
        assert "read_file(path (required), start, end)" in error
        assert "no tool called 'delete_everything'" in agent.repair_call("delete_everything", {}, by_name)[2]
    run(check)


def test_repaired_call_returns_the_lines_that_were_asked_for():
    """Before: read_file(line_start=80, line_end=84) silently returned lines 1-122."""
    async def check(tools):
        model = Script(
            AIMessage(content="", tool_calls=[
                call("functions.read_file", {"path": "app.py", "line_start": 80, "line_end": 84}, "1")]),
            AIMessage(content="done"),
        )
        decider = Decider()
        v = await agent.triage_candidate(agent.build_graph(model, tools, decider), fp01(), DEMO_APP, "m", 8)
        assert "app.py (lines 80-84 of" in decider.seen[-1].content
        assert v.tool_calls == ["read_file(path='app.py', start=80, end=84)"]
        assert v.repaired_calls == ["functions.read_file(path='app.py', line_start=80, line_end=84) -> "
                                    "read_file(path='app.py', start=80, end=84)"]
        assert agent.budget_report([v])["repaired_calls"] == 1
    run(check)


# Evidence check (step 18)


def test_agent_evidence_is_checked_against_what_it_read():
    """FP-01: after reading get_user, citing app.py:34 is verified; without reading
    it, the same claim is unseen and the false_positive goes to review."""
    claim = "app.py (line 34) casts the value with `uid = int(user_id)` before the call."

    async def check(tools):
        reads = Script(AIMessage(content="", tool_calls=[call("get_function", {"name": "get_user"}, "1")]),
                       AIMessage(content="done"))
        v = await agent.triage_candidate(agent.build_graph(reads, tools, Decider(reasoning=claim)),
                                         fp01(), DEMO_APP, "m", 8)
        assert v.verdict == "false_positive" and v.evidence_status == "verified"
        assert [(c.file, c.start_line) for c in v.evidence] == [("app.py", 34)]

        guesses = Script(AIMessage(content="done"))
        v = await agent.triage_candidate(agent.build_graph(guesses, tools, Decider(reasoning=claim)),
                                         fp01(), DEMO_APP, "m", 8)
        assert v.verdict == "needs_review" and v.original_verdict == "false_positive"
        assert v.evidence_status == "unseen" and "never shown" in v.missing_context
    run(check)
