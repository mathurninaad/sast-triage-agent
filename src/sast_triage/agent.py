"""Tool-using triage agent (milestone 3).

Same question as triage.py (is the claimed weakness real?), but instead of
judging a fixed window of code, the model can investigate the repository
with the eight read-only code tools, served by our MCP server, before it
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

Hardening, from the first real run (see parse_failure and repair_call):
- a reply the provider cannot parse (Groq: output_parse_failed / tool_use_failed)
  is retried with a short nudge, keeping what the model wrote; if it keeps
  failing, the agent stops investigating and decides with what it has;
- tool names with a namespace ("repo_browser.search_code") are resolved, and
  common wrong argument names ("line_start") are mapped to the real ones;
  anything else unknown is an error message listing the real parameters,
  never silently dropped;
- a call identical to an earlier one gets a one-line reply pointing back to
  the earlier result, instead of the same output again.

Every model call's token usage is added up on the verdict (tokens_in,
tokens_out, model_calls), so changes can be measured in tokens.

The model and the decider are passed in, so tests can script them.
"""

from __future__ import annotations

import json
import operator
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Annotated, Any, Awaitable, Callable, TypedDict

from langchain_core.messages import AIMessage, AnyMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import BaseTool, tool
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from sast_triage import evidence, triage
from sast_triage.models import Candidate
from sast_triage.triage import Judgement, Verdict

AGENT_PROMPT_VERSION = "agent-v5"
DEFAULT_BUDGET = 8       # base tool calls per candidate, before adjustments
MAX_BUDGET = 16          # hard ceiling, extension included
EXTENSION = 4            # calls granted by one request_more_budget
EXTENSION_TOOL = "request_more_budget"
PARSE_RETRIES = 2        # retries per model turn when the provider cannot parse the reply
PARSE_ERROR_CODES = ("output_parse_failed", "tool_use_failed")

# Wrong argument name -> real names to try, in order. One is used only if the tool
# has it and the call did not already set it.
ARG_ALIASES: dict[str, tuple[str, ...]] = {
    "start": ("line_start",), "start_line": ("line_start",), "from_line": ("line_start",),
    "end": ("line_end",), "end_line": ("line_end",), "to_line": ("line_end",),
    "limit": ("max_results",), "max": ("max_results",), "top_k": ("max_results",), "n": ("max_results",),
    "pattern": ("path",), "glob": ("path",), "file": ("path",), "file_path": ("path",),
    "filename": ("path",), "dir": ("path",), "directory": ("path",),
    "function_name": ("name", "function"), "symbol": ("name",), "func": ("function", "name"),
    "name": ("function",), "function": ("name",), "text": ("query",), "regexp": ("query",),
}

RETRY_NUDGE = """Your last reply could not be read: it was neither a well-formed tool call \
nor plain text. If you need more evidence, make one tool call using the exact tool and \
parameter names you were given. Otherwise reply in plain text with your summary."""

DECIDE_NUDGE = """Your previous answer could not be read. Answer again with only the \
structured verdict, filling every field."""


def parse_failure(exc: BaseException) -> str | None:
    """If `exc` is the provider rejecting a reply it could not parse, the text the
    model generated ('' if the error does not include it). None for any other error,
    which should not be retried here."""
    body = getattr(exc, "body", None)
    err = body.get("error", body) if isinstance(body, dict) else None
    if isinstance(err, dict) and err.get("code") in PARSE_ERROR_CODES:
        return str(err.get("failed_generation") or "")
    if any(code in str(exc) for code in PARSE_ERROR_CODES):
        return ""
    return None


def _schema(tool_: BaseTool) -> dict:
    schema = tool_.args_schema
    if isinstance(schema, dict):
        return schema
    return schema.model_json_schema() if schema is not None else {}


def _signature(tool_: BaseTool) -> str:
    schema = _schema(tool_)
    required = set(schema.get("required", []))
    params = [f"{p} (required)" if p in required else p for p in schema.get("properties", {})]
    return f"{tool_.name}({', '.join(params)})"


def repair_call(name: str, args: dict, tools: dict[str, BaseTool]) -> tuple[str, dict, str | None]:
    """Resolve a requested tool call against the real tools. Returns the tool name,
    the arguments to pass, and an error message for the model (or None).
    Namespaced names lose their prefix; known wrong argument names are mapped;
    any other unknown argument is reported, never silently dropped."""
    tool_ = tools.get(name) or tools.get(re.split(r"[.:/]", name)[-1])
    if tool_ is None:
        return name, args, f"Error: there is no tool called {name!r}. Available: {', '.join(tools)}"
    props = _schema(tool_).get("properties", {})
    fixed, unknown = {}, []
    for key, value in (args or {}).items():
        if key in props:
            fixed[key] = value
            continue
        target = next((t for t in ARG_ALIASES.get(key, ()) if t in props and t not in args), None)
        if target is None:
            unknown.append(key)
        elif value not in ("", None):  # an empty aliased value means "not set"
            fixed[target] = value
    if unknown:
        return tool_.name, args, (f"Error: {tool_.name} has no parameter {', '.join(map(repr, unknown))}. "
                                  f"Call it as {_signature(tool_)}.")
    return tool_.name, fixed, None


def call_key(name: str, args: dict, tool_: BaseTool) -> str:
    """Identity of a (repaired) call for spotting repeats: arguments equal to their
    default are dropped, so search_code(query='x') == search_code(query='x', regex=False)."""
    props = _schema(tool_).get("properties", {})
    kept = {k: v for k, v in args.items() if not ("default" in props.get(k, {}) and props[k]["default"] == v)}
    return f"{name}:{json.dumps(kept, sort_keys=True, default=str)}"


def _add_usage(state_in: int, state_out: int, usage: dict | None) -> dict:
    usage = usage or {}
    return {"tokens_in": state_in + int(usage.get("input_tokens") or 0),
            "tokens_out": state_out + int(usage.get("output_tokens") or 0)}


def _call_text(name: str, args: dict) -> str:
    return f"{name}({', '.join(f'{k}={v!r}' for k, v in args.items())})"


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

You can investigate the repository before deciding, using read-only tools. \
Paths are relative to the repository root. Each call costs time and tokens, so \
use the most direct tool.

First find the function the flagged lines are in: look for its definition (def, \
function, method signature) in the code shown above. Only if it is not there, call \
get_enclosing_function once with the flagged file and line, and use that name from \
then on; never call it again for the same line.

Then:
- trace_callers: who calls a function and with what data, code included (usually \
the first and often the only call you need);
- get_route_info: whether a function is reachable from a URL, and behind which checks;
- get_function: the full source of any other function or class;
- search_code: constants, settings and strings (not callers);
- read_file: only small ranges; never read whole files.
Never repeat a call: its result is still above.

Check the evidence your verdict depends on instead of assuming it:
- where the data at the flagged lines comes from: trace_callers on the enclosing \
function shows its callers and what they pass;
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
    trail: Annotated[list[str], operator.add]     # calls as actually run (after repair)
    call_keys: Annotated[list[str], operator.add]  # identities of the calls run, to spot repeats
    tokens_in: int
    tokens_out: int
    model_calls: int
    repaired: Annotated[list[str], operator.add]  # "asked -> ran" for corrected calls
    parse_retries: int   # unparseable replies retried so far
    gave_up: bool        # the model's replies kept failing to parse; decided early


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
    parse_retries: int = PARSE_RETRIES,
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
        """One model turn. A reply the provider cannot parse is retried with a nudge,
        keeping what the model wrote (usually its plan) in the conversation. After
        `parse_retries` failures the turn ends as plain text, which routes to finalize."""
        extra: list[AnyMessage] = []
        failures = 0
        while True:
            try:
                reply = await call_model(state["messages"] + extra)
                return {"messages": [*extra, reply], "parse_retries": state["parse_retries"] + failures,
                        "model_calls": state["model_calls"] + failures + 1,
                        **_add_usage(state["tokens_in"], state["tokens_out"], getattr(reply, "usage_metadata", None))}
            except Exception as exc:
                generated = parse_failure(exc)
                if generated is None:
                    raise
                failures += 1
                note = AIMessage(content=generated.strip() or "(the reply could not be read)")
                if failures > parse_retries:
                    return {"messages": [*extra, note], "gave_up": True,
                            "parse_retries": state["parse_retries"] + failures,
                            "model_calls": state["model_calls"] + failures}
                extra += [note, HumanMessage(RETRY_NUDGE)]

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
        results, trail, repaired, keys = [], [], [], []
        earlier = list(state["call_keys"])
        for call in calls:
            if call["name"] == EXTENSION_TOOL:
                if extended:
                    text = "Denied: the one extension for this candidate has already been used."
                elif budget >= max_budget:
                    text = f"Denied: the budget is already at the hard limit of {max_budget}."
                else:
                    budget, extended = min(budget + extension, max_budget), True
                    text = f"Granted: your budget is now {budget} tool calls."
                trail.append(_call_text(EXTENSION_TOOL, call["args"]))
            else:
                name, args, error = repair_call(call["name"], call["args"], by_name)
                key = call_key(name, args, by_name[name]) if not error else None
                if error:
                    text = error
                elif key in earlier:
                    text = ("Already run: this is the same call as an earlier one, and its result is "
                            "above. Use that result, or try a different call.")
                else:
                    try:
                        text = _tool_text(await by_name[name].ainvoke(args))
                    except Exception as exc:  # a broken call becomes a message the model can act on
                        text = f"Error: {type(exc).__name__}: {exc}"
                    if (name, args) != (call["name"], call["args"]):
                        repaired.append(f"{_call_text(call['name'], call['args'])} -> {_call_text(name, args)}")
                if key is not None and key in earlier:
                    trail.append(_call_text(name, args) + " [repeat]")
                else:
                    trail.append(_call_text(name, args) + (" [error]" if text.startswith("Error:") else ""))
                    if key is not None:
                        earlier.append(key)
                        keys.append(key)
                used += 1
            text += f"\n[calls left: {max(budget - used, 0)} of {budget}]"
            results.append(ToolMessage(content=text, tool_call_id=call["id"], name=call["name"]))
        return {"messages": results, "tool_calls_used": used, "budget": budget, "extended": extended,
                "trail": trail, "repaired": repaired, "call_keys": keys}

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
        if state["gave_up"]:
            log += ("\n[note] the investigation stopped early: your last replies could not be read. "
                    "Decide with the evidence above; if it is not enough, say what is missing.")
        final = opening + [HumanMessage(f"Investigation log:\n{log}\n\n{FINAL_INSTRUCTION}")]
        for attempt in range(parse_retries + 1):
            try:
                judgement, usage = triage.split_usage(await decide(final))
                return {"judgement": judgement, "model_calls": state["model_calls"] + attempt + 1,
                        **_add_usage(state["tokens_in"], state["tokens_out"], usage)}
            except Exception as exc:
                if parse_failure(exc) is None or attempt == parse_retries:
                    raise
                final = final + [HumanMessage(DECIDE_NUDGE)]

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


def _seen_text(messages: list[AnyMessage]) -> str:
    """Everything the model was shown: the opening evidence and every tool result
    (not its own notes, which are claims, not evidence)."""
    return "\n".join(_tool_text(m.content) for m in messages if isinstance(m, (HumanMessage, ToolMessage)))


async def triage_candidate(
    graph, candidate: Candidate, base_dir: Path, model: str, budget: int, max_budget: int = MAX_BUDGET,
    evidence_check: bool = True,
) -> Verdict:
    """Run the agent on one candidate with a starting budget. Import-only warnings
    use the fixed rule, and any failure keeps the candidate for human review.
    With evidence_check, the verdict's citations are checked against the code
    and against what the agent actually read (see evidence.py)."""
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
             "tool_calls_used": 0, "budget": budget, "extended": False, "judgement": None,
             "trail": [], "repaired": [], "parse_retries": 0, "gave_up": False,
             "call_keys": [], "tokens_in": 0, "tokens_out": 0, "model_calls": 0},
            config={"recursion_limit": 2 * max_budget + 10},
        )
    except Exception as exc:
        return Verdict(source_is_attacker_controlled="unclear", sanitized="unclear",
                       reasoning="Automatic triage failed; review manually.", verdict="needs_review",
                       confidence=0.0, error=f"{type(exc).__name__}: {exc}", tool_budget=budget, **meta)
    verdict = Verdict(**state["judgement"].model_dump(), tool_calls=state["trail"],
                      tool_budget=state["budget"], budget_extended=state["extended"],
                      parse_retries=state["parse_retries"], repaired_calls=state["repaired"],
                      repeated_calls=sum(1 for c in state["trail"] if c.endswith(" [repeat]")),
                      model_calls=state["model_calls"],
                      tokens_in=state["tokens_in"] or None, tokens_out=state["tokens_out"] or None, **meta)
    if evidence_check:
        verdict = evidence.check_verdict(verdict, candidate, base_dir, _seen_text(state["messages"]))
    return verdict


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
    evidence_check: bool = True,
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
        structured = llm.with_structured_output(Judgement, include_raw=True)

        async def call_model(messages):
            return await with_tools.ainvoke(messages)

        async def decide(messages):
            return triage.parse_structured(await structured.ainvoke(messages))

        graph = build_graph(call_model, tools, decide, max_budget=max_budget)
        verdicts = []
        for i, cand in enumerate(candidates, 1):
            if on_progress:
                on_progress(i, cand)
            start = budget_for(cand, budget, max_budget) if adaptive else min(budget, max_budget)
            verdicts.append(await triage_candidate(graph, cand, base_dir, model, start, max_budget,
                                                   evidence_check))
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
        "parse_retries": sum(v.parse_retries for v in ran),
        "repaired_calls": sum(len(v.repaired_calls) for v in ran),
        "repeated_calls": sum(v.repeated_calls for v in ran),
    }
