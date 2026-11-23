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

The tool budget is set per candidate (budget_for): bigger for severe
candidates and for data flows that cross files, smaller for low severity,
always within a hard ceiling. Every tool result shows the calls left, and
the model may ask once for an extension (request_more_budget) with a reason.
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
from langchain_core.tools import BaseTool, tool
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from sast_triage import triage
from sast_triage.models import Candidate
from sast_triage.triage import Judgement, Verdict

AGENT_PROMPT_VERSION = "agent-v2"
DEFAULT_BUDGET = 8       # base tool calls per candidate, before adjustments
MAX_BUDGET = 16          # hard ceiling, extension included
EXTENSION = 4            # calls granted by one request_more_budget
EXTENSION_TOOL = "request_more_budget"


def budget_for(candidate: Candidate, base: int = DEFAULT_BUDGET, maximum: int = MAX_BUDGET) -> int:
    """Tool budget for one candidate, from its own evidence:
    +2 for high/critical severity, -2 for low severity, and +4 when a
    scanner's data-flow trace crosses files (a longer chain to follow).
    Always between 2 and `maximum`."""
    budget = base
    severity = getattr(candidate.severity, "value", candidate.severity)
    if severity in ("high", "critical"):
        budget += 2
    elif severity == "low":
        budget -= 2
    if any(len({step.file for step in f.trace}) > 1 for f in candidate.findings):
        budget += 4
    return max(2, min(budget, maximum))


@tool(EXTENSION_TOOL)
def request_more_budget(reason: str) -> str:
    """Ask for more tool calls, once per candidate, when you are in the middle of an
    investigation (for example still following a chain of callers) and about to run
    out. Give a one-sentence reason. Grants a few more calls, up to a hard limit."""
    return ""  # handled by the graph itself; never actually executed

AGENT_GUIDANCE = """

You can investigate the repository before deciding, using read-only tools \
(get_function, find_references, get_route_info, search_code, read_file, list_files). \
Paths are relative to the repository root.

Check the evidence your verdict depends on instead of assuming it:
- where the data at the flagged lines comes from: get_function on the enclosing \
function, then find_references to see its callers and what they pass;
- whether it is validated or converted on the way, possibly in another file;
- whether the code is reachable from a request (get_route_info) and what guards it.

You may make at most {budget} tool calls; each tool result ends with how many you have \
left. Stop as soon as you have the evidence you need. If you are in the middle of \
following a chain and about to run out, you may call request_more_budget once, with a \
reason, for up to {extension} more calls (never more than {maximum} in total). \
When you are done, reply in plain text (no tool calls) with a short summary of what you \
found and where; the final verdict is asked for separately."""

FINAL_INSTRUCTION = """Based on the investigation above, give your final verdict on the \
claimed weakness. Cite the evidence you found (file and line). Use needs_review only if a \
specific piece of code you could not examine would change the answer, and name it."""

CallModel = Callable[[list[AnyMessage]], Awaitable[AIMessage]]
Decide = Callable[[list[AnyMessage]], Awaitable[Judgement]]


class AgentState(TypedDict):
    candidate: Candidate
    base_dir: str
    messages: Annotated[list[AnyMessage], add_messages]
    tool_calls_used: int
    budget: int          # this candidate's current budget (grows once if extended)
    extended: bool       # whether the one extension has been used
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


def build_graph(
    call_model: CallModel,
    tools: list[BaseTool],
    decide: Decide,
    max_budget: int = MAX_BUDGET,
    extension: int = EXTENSION,
):
    """The compiled LangGraph agent. `call_model` is the LLM with tools bound;
    `decide` returns the final Judgement. Each run's starting budget comes in
    the initial state (see budget_for)."""
    by_name = {t.name: t for t in tools}

    def prepare(state: AgentState) -> dict:
        system, human = triage.build_messages(state["candidate"], Path(state["base_dir"]))
        guidance = AGENT_GUIDANCE.format(budget=state["budget"], extension=extension, maximum=max_budget)
        return {"messages": [SystemMessage(system[1] + guidance), HumanMessage(human[1])]}

    async def agent(state: AgentState) -> dict:
        return {"messages": [await call_model(state["messages"])]}

    def route(state: AgentState) -> str:
        calls = getattr(state["messages"][-1], "tool_calls", None) or []
        if not calls:
            return "finalize"
        real = [c for c in calls if c["name"] != EXTENSION_TOOL]
        if not real and state["extended"]:
            return "finalize"  # asking again for an extension it already used: stop looping
        if state["tool_calls_used"] + len(real) <= state["budget"]:
            return "tools"
        return "finalize"

    async def run_tools(state: AgentState) -> dict:
        calls = state["messages"][-1].tool_calls
        used, budget, extended = state["tool_calls_used"], state["budget"], state["extended"]
        results = []
        for call in calls:
            if call["name"] == EXTENSION_TOOL:
                if extended:
                    text = "Denied: the one extension for this candidate has already been used."
                elif budget >= max_budget:
                    text = f"Denied: the budget is already at the hard limit of {max_budget}."
                else:
                    budget, extended = min(budget + extension, max_budget), True
                    text = f"Granted: your budget is now {budget} tool calls."
            else:
                tool_ = by_name.get(call["name"])
                if tool_ is None:
                    text = f"Error: there is no tool called {call['name']!r}. Available: {', '.join(by_name)}"
                else:
                    try:
                        text = _tool_text(await tool_.ainvoke(call["args"]))
                    except Exception as exc:  # a broken call becomes a message the model can act on
                        text = f"Error: {type(exc).__name__}: {exc}"
                used += 1
            text += f"\n[calls left: {max(budget - used, 0)} of {budget}]"
            results.append(ToolMessage(content=text, tool_call_id=call["id"], name=call["name"]))
        return {"messages": results, "tool_calls_used": used, "budget": budget, "extended": extended}

    async def finalize(state: AgentState) -> dict:
        messages = state["messages"]
        opening = [m for m in messages if isinstance(m, (SystemMessage, HumanMessage))][:2]
        log = _transcript(messages[2:])
        unanswered = getattr(messages[-1], "tool_calls", None) or []
        real = [c for c in unanswered if c["name"] != EXTENSION_TOOL]
        if real:
            log += (f"\n[note] {len(real)} more tool call(s) were not run: "
                    f"the budget of {state['budget']} was used up.")
        elif unanswered:
            log += "\n[note] another budget extension was requested and refused (only one is allowed)."
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


async def triage_candidate(
    graph, candidate: Candidate, base_dir: Path, model: str, budget: int, max_budget: int = MAX_BUDGET
) -> Verdict:
    """Run the agent on one candidate with a starting budget. Import-only warnings
    use the fixed rule, and any failure keeps the candidate for human review."""
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
             "tool_calls_used": 0, "budget": budget, "extended": False, "judgement": None},
            config={"recursion_limit": 2 * max_budget + 10},
        )
    except Exception as exc:
        return Verdict(source_is_attacker_controlled="unclear", sanitized="unclear",
                       reasoning="Automatic triage failed; review manually.", verdict="needs_review",
                       confidence=0.0, error=f"{type(exc).__name__}: {exc}", tool_budget=budget, **meta)
    return Verdict(**state["judgement"].model_dump(), tool_calls=_tool_trail(state["messages"]),
                   tool_budget=state["budget"], budget_extended=state["extended"], **meta)


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
    max_budget: int = MAX_BUDGET,
    adaptive: bool = True,
) -> list[Verdict]:
    """Triage candidates with the agent, using Groq and our MCP server.
    One MCP server process serves the whole run. With adaptive=True each
    candidate's budget comes from budget_for(); otherwise every candidate
    gets `budget`."""
    if not os.environ.get("GROQ_API_KEY"):
        raise RuntimeError("GROQ_API_KEY is not set. Put it in a .env file in the project folder.")
    from langchain_groq import ChatGroq
    from langchain_mcp_adapters.client import MultiServerMCPClient
    from langchain_mcp_adapters.tools import load_mcp_tools

    client = MultiServerMCPClient({"code": _server_command(base_dir)})
    async with client.session("code") as session:
        tools = await load_mcp_tools(session)
        llm = ChatGroq(model=model, temperature=0, max_retries=6)
        with_tools = llm.bind_tools([*tools, request_more_budget])
        structured = llm.with_structured_output(Judgement)

        async def call_model(messages):
            return await with_tools.ainvoke(messages)

        async def decide(messages):
            result = await structured.ainvoke(messages)
            if not isinstance(result, Judgement):
                raise ValueError(f"model returned {type(result).__name__}, not a Judgement")
            return result

        graph = build_graph(call_model, tools, decide, max_budget=max_budget)
        verdicts = []
        for i, cand in enumerate(candidates, 1):
            if on_progress:
                on_progress(i, cand)
            start = budget_for(cand, budget, max_budget) if adaptive else min(budget, max_budget)
            verdicts.append(await triage_candidate(graph, cand, base_dir, model, start, max_budget))
        return verdicts


def budget_report(verdicts: list[Verdict]) -> dict:
    """How the tool budget was used, for the agent candidates (rule-based ones excluded)."""
    ran = [v for v in verdicts if v.prompt_version == AGENT_PROMPT_VERSION and v.model != "rule:import-warning"]
    counts = sorted(len([c for c in v.tool_calls if not c.startswith(EXTENSION_TOOL)]) for v in ran)
    if not counts:
        return {"candidates": 0}
    return {
        "candidates": len(ran),
        "median_calls": counts[len(counts) // 2],
        "max_calls": counts[-1],
        "hit_budget": sum(1 for v in ran if v.tool_budget and
                          len([c for c in v.tool_calls if not c.startswith(EXTENSION_TOOL)]) >= v.tool_budget),
        "extended": sum(1 for v in ran if v.budget_extended),
    }
