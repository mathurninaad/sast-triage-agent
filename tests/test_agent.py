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
        return self.replies.pop(0) if self.replies else AIMessage(content="done")


class Decider:
    def __init__(self, verdict="false_positive", fail=False):
        self.verdict, self.fail, self.seen = verdict, fail, None

    async def __call__(self, messages):
        self.seen = messages
        if self.fail:
            raise TimeoutError("rate limited")
        return Judgement(weakness_under_review="SQL injection (CWE-89), db.py 23-24",
                         source_is_attacker_controlled="yes", sanitized="yes",
                         reasoning="app.py:34 converts with int().", missing_context=None,
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
        graph = agent.build_graph(model, tools, decider, budget=8)
        v = await agent.triage_candidate(graph, fp01(), DEMO_APP, "test-model", 8)

        assert v.verdict == "false_positive" and v.prompt_version == agent.AGENT_PROMPT_VERSION
        assert v.tool_calls == ["find_references(name='get_user_by_id')", "get_function(name='get_user')"]
        log = decider.seen[-1].content
        assert "app.py:35 [call] in get_user" in log           # real tool output, via MCP
        assert "uid = int(user_id)" in log
        assert "The only caller converts" in log               # the model's own notes
        assert "Judge only that claimed weakness" in decider.seen[0].content  # same base prompt as M2
        assert "at most 8 tool calls" in model.inputs[0][0].content          # agent guidance + budget
    run(check)


def test_budget_is_enforced_by_code():
    """A model that never stops asking gets exactly `budget` calls, then must decide."""
    async def check(tools):
        endless = Script(*[AIMessage(content="", tool_calls=[call("list_files", {}, str(i))]) for i in range(20)])
        decider = Decider()
        graph = agent.build_graph(endless, tools, decider, budget=3)
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
