"""The code-navigation tools. Each takes a Repo plus simple arguments and
returns plain text for an LLM to read, kept short by hard caps.

  list_files       what files exist
  read_file        a range of lines
  search_code      text or regex search across files
  get_function     a function or class definition, with its decorators
  find_references  where a function is called (from the syntax tree, so names
                   in comments or strings don't count)
  get_route_info   which URL reaches a view function, with which decorators

The structural tools (get_function, find_references, get_route_info) cover
Python through the standard library's `ast`, and JavaScript, TypeScript,
Java, Go and Ruby through tree-sitter (see treesitter.py).

Bad requests raise RepoError with a message meant for the agent.
"""

from __future__ import annotations

import ast
import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path

from sast_triage.context import treesitter as tsx
from sast_triage.context.repo import Repo, RepoError

MAX_OUTPUT_CHARS = 8000
MAX_READ_LINES = 150
MAX_DEF_LINES = 150
MAX_LINE_CHARS = 200

ROUTE_METHODS = {"route", "get", "post", "put", "patch", "delete", "api_route", "websocket"}
DJANGO_URL_FUNCS = {"path", "re_path", "url"}
AUTH_HINTS = ("login", "auth", "permission", "require", "admin", "staff", "token", "jwt")


def _cap(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... (output cut at {limit} characters; narrow the request)"


def _short(line: str) -> str:
    line = line.rstrip()
    return line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS] + " ..."


def _numbered(lines: list[str], start: int, end: int) -> str:
    width = len(str(end))
    return "\n".join(f"{n:>{width}} | {_short(lines[n - 1])}" for n in range(start, end + 1))


@dataclass
class _Def:
    name: str
    qualname: str
    start: int   # first decorator line, or the def line
    end: int
    node: ast.AST


def _definitions(tree: ast.Module) -> list[_Def]:
    """Every function/method/class in a module, with qualified names like 'Cls.method'."""
    found: list[_Def] = []

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qual = f"{prefix}{child.name}"
                start = min([d.lineno for d in child.decorator_list] + [child.lineno])
                found.append(_Def(child.name, qual, start, child.end_lineno or child.lineno, child))
                visit(child, qual + ".")
            else:
                visit(child, prefix)

    visit(tree, "")
    return found


def _enclosing(defs: list[_Def], line: int) -> str:
    """Innermost function/class containing a line, or '<module>'."""
    inside = [d for d in defs if d.start <= line <= d.end and not isinstance(d.node, ast.ClassDef)]
    if not inside:
        inside = [d for d in defs if d.start <= line <= d.end]
    return max(inside, key=lambda d: d.start).qualname if inside else "<module>"


STRUCTURED_EXTENSIONS = frozenset({".py"}) | tsx.SUPPORTED_EXTENSIONS


def _source_files(repo: Repo, file: str | None) -> list[Path]:
    """Files the structural tools understand: Python plus the tree-sitter languages."""
    if file:
        path = repo.resolve(file)
        if not path.is_file():
            raise RepoError(f"no such file: {file}")
        if path.suffix.lower() not in STRUCTURED_EXTENSIONS:
            raise RepoError(
                f"{file}: this tool understands {', '.join(sorted(STRUCTURED_EXTENSIONS))} files; "
                "use read_file or search_code for others"
            )
        return [path]
    return [p for p in repo.files() if p.suffix.lower() in STRUCTURED_EXTENSIONS]


def _ts_tree(path: Path):
    """(tree, spec) for a tree-sitter language file, or (None, None)."""
    spec = tsx.spec_for(path)
    if spec is None or path.stat().st_size > 1_000_000:
        return None, None
    return tsx.parse(path, spec), spec


# The tools


def list_files(repo: Repo, pattern: str = "*", limit: int = 200) -> str:
    """Files whose repo-relative path matches a glob pattern, e.g. '*.py' or 'app/*'."""
    matches = [repo.rel(p) for p in repo.files() if fnmatch.fnmatch(repo.rel(p), pattern)]
    if not matches:
        return f"No files match {pattern!r}."
    shown = matches[:limit]
    more = f"\n... and {len(matches) - limit} more" if len(matches) > limit else ""
    return _cap(f"{len(matches)} files match {pattern!r}:\n" + "\n".join(shown) + more)


def read_file(repo: Repo, path: str, start: int = 1, end: int | None = None) -> str:
    """Lines start..end of a file (1-based, inclusive), numbered; at most 150 lines."""
    lines = repo.read_lines(path)
    if not lines:
        return f"{path} is empty."
    start = max(1, start)
    if start > len(lines):
        raise RepoError(f"{path} has only {len(lines)} lines")
    end = min(len(lines), end if end is not None else start + MAX_READ_LINES - 1)
    note = ""
    if end - start + 1 > MAX_READ_LINES:
        end = start + MAX_READ_LINES - 1
        note = f"\n(showing {MAX_READ_LINES} lines; ask for the next range to continue)"
    return _cap(f"{path} (lines {start}-{end} of {len(lines)}):\n{_numbered(lines, start, end)}{note}")


def search_code(repo: Repo, query: str, regex: bool = False, pattern: str = "*", limit: int = 40) -> str:
    """Lines containing `query` (plain text, or a regex if regex=True) in files matching `pattern`."""
    if not query:
        raise RepoError("query must not be empty")
    try:
        matcher = re.compile(query) if regex else None
    except re.error as exc:
        raise RepoError(f"invalid regex {query!r}: {exc}") from None
    hits: list[str] = []
    total = 0
    for path in repo.files():
        rel = repo.rel(path)
        if not fnmatch.fnmatch(rel, pattern):
            continue
        try:
            lines = repo.read_lines(rel)
        except RepoError:
            continue
        for n, line in enumerate(lines, 1):
            if len(line) > 2000:  # minified or generated code: skip (and keep regexes fast)
                continue
            if (matcher.search(line) if matcher else query in line):
                total += 1
                if len(hits) < limit:
                    hits.append(f"{rel}:{n}: {_short(line.strip())}")
    if not hits:
        return f"No matches for {query!r}."
    more = f"\n... {total - limit} more matches; narrow the query or pattern" if total > limit else ""
    return _cap(f"{total} matches for {query!r}:\n" + "\n".join(hits) + more)


def get_function(repo: Repo, name: str, file: str | None = None) -> str:
    """Source of every function, method or class called `name` ('Cls.method' also
    works), including its decorators or annotations, with line numbers."""
    out: list[str] = []
    for path in _source_files(repo, file):
        rel = repo.rel(path)
        if path.suffix.lower() == ".py":
            tree = repo.parse(path)
            found = [(d.qualname, d.start, d.end) for d in _definitions(tree) if name in (d.name, d.qualname)] if tree else []
        else:
            ts_tree, spec = _ts_tree(path)
            found = [(d.qualname, d.start, d.end) for d in tsx.definitions(ts_tree, spec)
                     if name in (d.name, d.qualname)] if ts_tree else []
        if not found:
            continue
        lines = repo.read_lines(rel)
        for qualname, start, end_line in found:
            end = min(end_line, start + MAX_DEF_LINES - 1)
            cut = f"\n(definition continues to line {end_line})" if end < end_line else ""
            out.append(f"{rel}:{start}-{end_line} ({qualname}):\n{_numbered(lines, start, end)}{cut}")
    if not out:
        return f"No function or class named {name!r} found" + (f" in {file}." if file else ".")
    return _cap("\n\n".join(out[:5]) + (f"\n\n... {len(out) - 5} more definitions" if len(out) > 5 else ""))


def find_references(repo: Repo, name: str, limit: int = 50) -> str:
    """Every place `name` is called (as name(...) or obj.name(...)) or imported,
    with the function it happens in. Names in comments and strings don't count."""
    hits: list[tuple[str, int, str, str]] = []
    for path in _source_files(repo, None):
        rel = repo.rel(path)
        if path.suffix.lower() != ".py":
            ts_tree, spec = _ts_tree(path)
            if ts_tree is not None:
                hits += [(rel, line, kind, where) for line, kind, where in tsx.references(ts_tree, spec, name)]
            continue
        tree = repo.parse(path)
        if tree is None:
            continue
        defs = _definitions(tree)
        for node in ast.walk(tree):
            kind = None
            if isinstance(node, ast.Call):
                f = node.func
                if (isinstance(f, ast.Name) and f.id == name) or (isinstance(f, ast.Attribute) and f.attr == name):
                    kind = "call"
            elif isinstance(node, ast.ImportFrom) and any(a.name == name for a in node.names):
                kind = "import"
            if kind:
                hits.append((rel, node.lineno, kind, _enclosing(defs, node.lineno)))
    if not hits:
        return f"No calls to or imports of {name!r} found (it may be unused, or only used dynamically)."
    hits = sorted(set(hits))
    shown = [
        f"{rel}:{line} [{kind}] in {where}: {_short(repo.read_lines(rel)[line - 1].strip())}"
        for rel, line, kind, where in hits[:limit]
    ]
    more = f"\n... {len(hits) - limit} more" if len(hits) > limit else ""
    return _cap(f"{len(hits)} references to {name!r}:\n" + "\n".join(shown) + more)


def _decorator_route(dec: ast.expr) -> str | None:
    """'@app.route("/x", methods=["POST"])' -> 'POST /x' (Flask/FastAPI style), else None."""
    if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
        return None
    if dec.func.attr not in ROUTE_METHODS or not dec.args:
        return None
    first = dec.args[0]
    url = first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else ast.unparse(first)
    methods = dec.func.attr.upper() if dec.func.attr not in ("route", "api_route") else "GET"
    for kw in dec.keywords:
        if kw.arg == "methods":
            try:
                methods = ",".join(ast.literal_eval(kw.value))
            except (ValueError, SyntaxError):
                methods = ast.unparse(kw.value)
    return f"{methods} {url}"


def _django_routes(repo: Repo, name: str) -> list[str]:
    """path()/re_path()/url() entries in urls.py files that point at `name`."""
    found = []
    for path in repo.files("urls.py"):
        tree = repo.parse(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in DJANGO_URL_FUNCS and len(node.args) >= 2):
                continue
            target = node.args[1]
            names = {n.attr for n in ast.walk(target) if isinstance(n, ast.Attribute)}
            names |= {n.id for n in ast.walk(target) if isinstance(n, ast.Name)}
            if name in names:
                found.append(f"{repo.rel(path)}:{node.lineno}: {_short(ast.unparse(node))}")
    return found


def get_route_info(repo: Repo, function: str, file: str | None = None) -> str:
    """Whether `function` is a web endpoint: its URL(s) and HTTP methods and its
    other decorators/annotations, e.g. login checks. Understands Flask/FastAPI
    decorators and Django urls.py (Python), Express-style router calls
    (JavaScript/TypeScript), Go net/http and similar routers, and Spring/NestJS
    route annotations."""
    out: list[str] = []
    has_route = False
    for path in _source_files(repo, file):
        rel = repo.rel(path)
        if path.suffix.lower() == ".py":
            tree = repo.parse(path)
            if tree is None:
                continue
            for d in _definitions(tree):
                if d.name != function or isinstance(d.node, ast.ClassDef):
                    continue
                decs = d.node.decorator_list  # type: ignore[attr-defined]
                routes = [r for r in (_decorator_route(x) for x in decs) if r]
                others = [ast.unparse(x) for x in decs if not _decorator_route(x)]
                has_route = has_route or bool(routes)
                out.append(_route_block(rel, d.start, d.qualname, routes, others))
        else:
            ts_tree, spec = _ts_tree(path)
            if ts_tree is None:
                continue
            for d in tsx.definitions(ts_tree, spec):
                if d.name != function or d.kind == "class":
                    continue
                routes = tsx.annotation_routes(d, spec)
                decs = tsx.decorators_of(d.node, spec)
                others = [x for x in decs if not any(x.lstrip("@").startswith(k) for k in tsx.ROUTE_ANNOTATIONS)]
                has_route = has_route or bool(routes)
                out.append(_route_block(rel, d.start, d.qualname, routes, others))
    router = []
    routes_found, mounted = [], []
    for path in _source_files(repo, None):
        ts_tree, spec = _ts_tree(path) if path.suffix.lower() != ".py" else (None, None)
        if ts_tree is None:
            continue
        routes_found += [(repo.rel(path), r) for r in tsx.router_routes(ts_tree, spec, function)]
        mounted += [(repo.rel(path), m) for m in tsx.path_middleware(ts_tree, spec)]
    for rel, r in routes_found:
        line = f"  {rel}:{r.line}: {r.route}"
        checks = [m for m in r.middleware if any(h in m.lower() for h in AUTH_HINTS)]
        if r.middleware:
            line += f" (middleware before it: {', '.join(r.middleware)})"
        # app.use('/prefix', ...) middleware that also runs for this route
        for m_rel, m in mounted:
            if tsx.covers(m.path, r.path) and m.middleware:
                line += f"\n    also runs app.use middleware for {m.path or '/'} ({m_rel}:{m.line}): {', '.join(m.middleware)}"
                checks += [x for x in m.middleware if any(h in x.lower() for h in AUTH_HINTS)]
        if checks:
            line += f"\n    looks like an access check: {', '.join(dict.fromkeys(checks))}"
        router.append(line)
    if router:
        has_route = True
        out.append("Router calls registering it as a handler:\n" + "\n".join(router))
    django = _django_routes(repo, function)
    if django:
        has_route = True
        out.append("Django URL patterns pointing at it:\n" + "\n".join(f"  {x}" for x in django))
    if not out:
        return f"No function named {function!r} found" + (f" in {file}." if file else ".")
    if not has_route:
        out.append("No route found: it may not be reachable from a URL directly (check its callers).")
    return _cap("\n".join(out))


def _route_block(rel: str, start: int, qualname: str, routes: list[str], others: list[str]) -> str:
    auth = [o for o in others if any(h in o.lower() for h in AUTH_HINTS)]
    shown = ", ".join(o if o.startswith("@") else "@" + o for o in others)
    lines = [f"{rel}:{start} {qualname}",
             f"  routes: {', '.join(routes) if routes else 'none from decorators'}",
             f"  other decorators: {shown or 'none'}"]
    if auth:
        lines.append(f"  looks like an access check: {', '.join(a if a.startswith('@') else '@' + a for a in auth)}")
    return "\n".join(lines)


TOOLS = {
    "list_files": list_files,
    "read_file": read_file,
    "search_code": search_code,
    "get_function": get_function,
    "find_references": find_references,
    "get_route_info": get_route_info,
}
