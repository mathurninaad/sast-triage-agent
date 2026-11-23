"""Tool-using triage agent (milestone 3).

Same question as triage.py (is the claimed weakness real?), but instead of
judging a fixed window of code, the model can investigate the repository
with the six read-only code tools, served by our MCP server, before it
decides. LangGraph runs the loop:

    START -> prepare -> agent -> route --(tool calls, budget left)--> tools -> agent
                                     \\--(done, or budget used up)----> finalize -> END

- prepare:  the same opening evidence as single-shot triage, plus tool guidance
- agent:    the LLM, with the tools bound, either requests tool calls or stops
- route:    plain code: go to tools only if calls were requested and the
            budget allows them (the model cannot talk its way past it)
- tools:    runs the requested calls and adds the results to the conversation
- finalize: one more LLM call that must return the strict Judgement schema,
            given a plain-text log of the investigation

The model and the decider are passed in, so tests can script them.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Annotated, Any, Awaitable, Callable, TypedDict

from langchain_core.messages import AIMessage, AnyMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import BaseTool
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from sast_triage import triage
from sast_triage.models import Candidate
from sast_triage.triage import Judgement, Verdict

AGENT_PROMPT_VERSION = "agent-v1"
DEFAULT_BUDGET = 8

AGENT_GUIDANCE = """

You can investigate the repository before deciding, using read-only tools \\
(get_function, find_references, get_route_info, search_code, read_file, list_files). \\
Paths are relative to the repository root.

Check the evidence your verdict depends on instead of assuming it:
- where the data at the flagged lines comes from: get_function on the enclosing \\
function, then find_references to see its callers and what they pass;
- whether it is validated or converted on the way, possibly in another file;
- whether the code is reachable from a request (get_route_info) and what guards it.

You may make at most {budget} tool calls. Stop as soon as you have the evidence you need. \\
When you are done, reply in plain text (no tool calls) with a short summary of what you \\
found and where; the final verdict is asked for separately."""

FINAL_INSTRUCTION = """Based on the investigation above, give your final verdict on the \\
claimed weakness. Cite the evidence you found (file and line). Use needs_review only if a \\
specific piece of code you could not examine would change the answer, and name it."""

CallModel = Callable[[list[AnyMessage]], Awaitable[AIMessage]]
Decide = Callable[[list[AnyMessage]], Awaitable[Judgement]]


class AgentState(TypedDict):
    candidate: Candidate
    base_dir: str
    messages: Annotated[list[AnyMessage], add_messages]
    tool_calls_used: int
    judgement: Judgement | None


def _tool_text(result: Any) -> str:
    """MCP tool results arrive as a list of content blocks; join their text."""
    if isinstance(result, list):
        return "\n".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in result)
    return str(result)


def _transcript(messages: list[AnyMessage]) -> str:
    """A plain-text log of the investigation, for the final structured call.
    (Plain text avoids replaying tool-call messages to a model that has no tools bound.)"""
    lines = []
    for m in messages:
        if isinstance(m, AIMessage):
            for call in m.tool_calls or []:
                lines.append(f"[tool call] {call['name']}({json.dumps(call['args'])})")
            if isinstance(m.content, str) and m.content.strip():
                lines.append(f"[your notes] {m.content.strip()}")
        elif isinstance(m, ToolMessage):
            lines.append(f"[tool result]\n<code>\n{_tool_text(m.content)}\n</code>")
    return "\n".join(lines) or "(no tools were called)"


def build_graph(call_model: CallModel, tools: list[BaseTool], decide: Decide, budget: int = DEFAULT_BUDGET):
    """The compiled LangGraph agent. `call_model` is the LLM with tools bound;
    `decide` returns the final Judgement."""
    by_name = {t.name: t for t in tools}

    def prepare(state: AgentState) -> dict:
        system, human = triage.build_messages(state["candidate"], Path(state["base_dir"]))
        return {"messages": [
            SystemMessage(system[1] + AGENT_GUIDANCE.format(budget=budget)),
            HumanMessage(human[1]),
        ]}

    async def agent(state: AgentState) -> dict:
        return {"messages": [await call_model(state["messages"])]}

    def route(state: AgentState) -> str:
        calls = getattr(state["messages"][-1], "tool_calls", None) or []
        if calls and state["tool_calls_used"] + len(calls) <= budget:
            return "tools"
        return "finalize"

    async def run_tools(state: AgentState) -> dict:
        calls = state["messages"][-1].tool_calls
        results = []
        for call in calls:
            tool = by_name.get(call["name"])
            if tool is None:
                text = f"Error: there is no tool called {call['name']!r}. Available: {', '.join(by_name)}"
            else:
                try:
                    text = _tool_text(await tool.ainvoke(call["args"]))
                except Exception as exc:  # a broken call becomes a message the model can act on
                    text = f"Error: {type(exc).__name__}: {exc}"
            results.append(ToolMessage(content=text, tool_call_id=call["id"], name=call["name"]))
        return {"messages": results, "tool_calls_used": state["tool_calls_used"] + len(calls)}

    async def finalize(state: AgentState) -> dict:
        messages = state["messages"]
        opening = [m for m in messages if isinstance(m, (SystemMessage, HumanMessage))][:2]
        log = _transcript(messages[2:])
        unanswered = getattr(messages[-1], "tool_calls", None)
        if unanswered:
            log += f"\n[note] {len(unanswered)} more tool call(s) were not run: the budget of {budget} was used up."
        final = opening + [HumanMessage(f"Investigation log:\n{log}\n\n{FINAL_INSTRUCTION}")]
        return {"judgement": await decide(final)}

    graph = StateGraph(AgentState)
    graph.add_node("prepare", prepare)
    graph.add_node("agent", agent)
    graph.add_node("tools", run_tools)
    graph.add_node("finalize", finalize)
    graph.add_edge(START, "prepare")
    graph.add_edge("prepare", "agent")
    graph.add_conditional_edges("agent", route, {"tools": "tools", "finalize": "finalize"})
    graph.add_edge("tools", "agent")
    graph.add_edge("finalize", END)
    return graph.compile()


def _tool_trail(messages: list[AnyMessage]) -> list[str]:
    """The tool calls that were actually run (they have a result), in order.
    Calls the model requested after the budget ran out are not included."""
    ran = {m.tool_call_id for m in messages if isinstance(m, ToolMessage)}
    trail = []
    for m in messages:
        if isinstance(m, AIMessage):
            for call in m.tool_calls or []:
                if call["id"] in ran:
                    args = ", ".join(f"{k}={v!r}" for k, v in call["args"].items())
                    trail.append(f"{call['name']}({args})")
    return trail


async def triage_candidate(graph, candidate: Candidate, base_dir: Path, model: str, budget: int) -> Verdict:
    """Run the agent on one candidate. Import-only warnings use the fixed rule,
    and any failure keeps the candidate for human review with the error noted."""
    if triage.is_import_warning_only(candidate):
        def never(_):
            raise AssertionError("not called")
        verdict = triage.triage_candidate(candidate, base_dir, never, model)
        return verdict.model_copy(update={"prompt_version": AGENT_PROMPT_VERSION})
    meta = dict(candidate_id=candidate.id, file=candidate.file, start_line=candidate.start_line,
                end_line=candidate.end_line, model=model, prompt_version=AGENT_PROMPT_VERSION)
    try:
        state = await graph.ainvoke(
            {"candidate": candidate, "base_dir": str(base_dir), "messages": [],
             "tool_calls_used": 0, "judgement": None},
            config={"recursion_limit": 2 * budget + 10},
        )
    except Exception as exc:
        return Verdict(source_is_attacker_controlled="unclear", sanitized="unclear",
                       reasoning="Automatic triage failed; review manually.", verdict="needs_review",
                       confidence=0.0, error=f"{type(exc).__name__}: {exc}", **meta)
    return Verdict(**state["judgement"].model_dump(), tool_calls=_tool_trail(state["messages"]), **meta)


def _server_command(base_dir: Path) -> dict:
    """How to start our MCP server for this repo as a subprocess (stdio)."""
    exe = Path(sys.executable).with_name("sast-triage")
    command = str(exe) if exe.exists() else (shutil.which("sast-triage") or "sast-triage")
    return {
        "command": command,
        "args": ["mcp-server", str(base_dir)],
        "transport": "stdio",
        "env": {**os.environ, "SAST_TRIAGE_QUIET": "1"},
    }


async def triage_all(
    candidates: list[Candidate],
    base_dir: Path,
    model: str = triage.DEFAULT_MODEL,
    budget: int = DEFAULT_BUDGET,
    on_progress: Callable[[int, Candidate], None] | None = None,
) -> list[Verdict]:
    """Triage candidates with the agent, using Groq and our MCP server.
    One MCP server process serves the whole run."""
    if not os.environ.get("GROQ_API_KEY"):
        raise RuntimeError("GROQ_API_KEY is not set. Put it in a .env file in the project folder.")
    from langchain_groq import ChatGroq
    from langchain_mcp_adapters.client import MultiServerMCPClient
    from langchain_mcp_adapters.tools import load_mcp_tools

    client = MultiServerMCPClient({"code": _server_command(base_dir)})
    async with client.session("code") as session:
        tools = await load_mcp_tools(session)
        llm = ChatGroq(model=model, temperature=0, max_retries=6)
        with_tools = llm.bind_tools(tools)
        structured = llm.with_structured_output(Judgement)

        async def call_model(messages):
            return await with_tools.ainvoke(messages)

        async def decide(messages):
            result = await structured.ainvoke(messages)
            if not isinstance(result, Judgement):
                raise ValueError(f"model returned {type(result).__name__}, not a Judgement")
            return result

        graph = build_graph(call_model, tools, decide, budget)
        verdicts = []
        for i, cand in enumerate(candidates, 1):
            if on_progress:
                on_progress(i, cand)
            verdicts.append(await triage_candidate(graph, cand, base_dir, model, budget))
        return verdicts
