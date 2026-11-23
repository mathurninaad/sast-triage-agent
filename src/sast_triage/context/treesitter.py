"""Code structure for non-Python languages, via tree-sitter.

tree-sitter parses source into a syntax tree for many languages. Each
language here is described by a small LangSpec table (which node types are
definitions, which are calls, which field holds a name), and one generic
walker uses that table to answer the same questions the Python `ast` code
answers for .py files:

  - definitions: functions, methods, classes (with qualified names and the
    decorators/annotations that belong to them)
  - references: where a name is called, and from which function
  - routes: URL handlers declared by a router call (Express, Go net/http,
    Gin, ...) or by an annotation/decorator (Spring, NestJS)

Python stays on the standard library's `ast` (see tools.py): it is exact,
built in, and already handles decorators and qualified names.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable

import tree_sitter as ts
import tree_sitter_go
import tree_sitter_java
import tree_sitter_javascript
import tree_sitter_ruby
import tree_sitter_typescript


@dataclass(frozen=True)
class LangSpec:
    name: str
    extensions: tuple[str, ...]
    language: Callable[[], object]
    # node type -> kind ("function", "method", "class"); its name is in the "name" field
    defs: dict[str, str]
    # node type -> fields that may hold the callee, tried in order
    calls: dict[str, tuple[str, ...]]
    # member/selector node type -> field holding the member name (obj.<name>)
    members: dict[str, str] = field(default_factory=dict)
    # node types that are decorators placed before a definition (TypeScript)
    decorators: tuple[str, ...] = ()
    # variable declarations whose value is a function, e.g. `const h = (req) => ...`
    function_values: tuple[str, ...] = ()
    # node types holding a plain string literal
    strings: tuple[str, ...] = ("string",)


_JS_DEFS = {
    "function_declaration": "function",
    "generator_function_declaration": "function",
    "method_definition": "method",
    "class_declaration": "class",
    "variable_declarator": "function",  # only when its value is a function (checked)
}
_JS_CALLS = {"call_expression": ("function",), "new_expression": ("constructor",)}
_JS_FUNCTION_VALUES = ("arrow_function", "function_expression", "function")

SPECS: tuple[LangSpec, ...] = (
    LangSpec(
        name="javascript", extensions=(".js", ".jsx", ".mjs", ".cjs"),
        language=tree_sitter_javascript.language,
        defs=_JS_DEFS, calls=_JS_CALLS, members={"member_expression": "property"},
        decorators=("decorator",), function_values=_JS_FUNCTION_VALUES,
    ),
    LangSpec(
        name="typescript", extensions=(".ts",),
        language=tree_sitter_typescript.language_typescript,
        defs={**_JS_DEFS, "interface_declaration": "class", "abstract_class_declaration": "class"},
        calls=_JS_CALLS, members={"member_expression": "property"},
        decorators=("decorator",), function_values=_JS_FUNCTION_VALUES,
    ),
    LangSpec(
        name="tsx", extensions=(".tsx",),
        language=tree_sitter_typescript.language_tsx,
        defs={**_JS_DEFS, "interface_declaration": "class", "abstract_class_declaration": "class"},
        calls=_JS_CALLS, members={"member_expression": "property"},
        decorators=("decorator",), function_values=_JS_FUNCTION_VALUES,
    ),
    LangSpec(
        name="java", extensions=(".java",),
        language=tree_sitter_java.language,
        defs={
            "method_declaration": "method",
            "constructor_declaration": "method",
            "class_declaration": "class",
            "interface_declaration": "class",
            "enum_declaration": "class",
            "record_declaration": "class",
        },
        calls={"method_invocation": ("name",), "object_creation_expression": ("type",)},
        strings=("string_literal",),
    ),
    LangSpec(
        name="go", extensions=(".go",),
        language=tree_sitter_go.language,
        defs={"function_declaration": "function", "method_declaration": "method", "type_spec": "class"},
        calls={"call_expression": ("function",)},
        members={"selector_expression": "field"},
        strings=("interpreted_string_literal", "raw_string_literal"),
    ),
    LangSpec(
        name="ruby", extensions=(".rb",),
        language=tree_sitter_ruby.language,
        defs={"method": "method", "singleton_method": "method", "class": "class", "module": "class"},
        calls={"call": ("method",)},
    ),
)

_BY_EXT = {ext: spec for spec in SPECS for ext in spec.extensions}
SUPPORTED_EXTENSIONS = frozenset(_BY_EXT)

# Router calls that declare a URL handler: app.get("/x", h), http.HandleFunc("/x", h), r.GET(...)
ROUTER_METHODS = {"get", "post", "put", "patch", "delete", "all", "use", "options", "head",
                  "handle", "handlefunc", "any", "route"}
# Annotations / decorators that declare a URL handler (Spring, NestJS)
ROUTE_ANNOTATIONS = {
    "GetMapping": "GET", "PostMapping": "POST", "PutMapping": "PUT", "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH", "RequestMapping": "ANY",
    "Get": "GET", "Post": "POST", "Put": "PUT", "Delete": "DELETE", "Patch": "PATCH", "All": "ANY",
}


def spec_for(path: Path) -> LangSpec | None:
    return _BY_EXT.get(path.suffix.lower())


@lru_cache(maxsize=16)
def _parser(name: str) -> ts.Parser:
    spec = next(s for s in SPECS if s.name == name)
    return ts.Parser(ts.Language(spec.language()))


@lru_cache(maxsize=512)
def _parse_cached(path: str, name: str, _mtime: int, _size: int) -> ts.Tree:
    return _parser(name).parse(Path(path).read_bytes())


def parse(path: Path, spec: LangSpec) -> ts.Tree:
    """Parsed file, cached per file version. tree-sitter always returns a tree,
    even for code with syntax errors (it marks the broken parts)."""
    st = path.stat()
    return _parse_cached(str(path), spec.name, st.st_mtime_ns, st.st_size)


def _text(node: ts.Node | None) -> str:
    return node.text.decode(errors="replace") if node is not None and node.text else ""


def _walk(node: ts.Node):
    """Every node in the tree, depth first (iteratively, so deep files are fine)."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


# Definitions


@dataclass
class Definition:
    name: str
    qualname: str
    kind: str
    start: int  # 1-based; includes preceding decorators
    end: int
    node: ts.Node


def _def_name(node: ts.Node, spec: LangSpec) -> str | None:
    """The definition's name, or None if this node isn't really a definition."""
    if node.type not in spec.defs:
        return None
    if node.type == "variable_declarator":
        value = node.child_by_field_name("value")
        if value is None or value.type not in spec.function_values:
            return None  # an ordinary variable, not a function
    name = node.child_by_field_name("name")
    if name is None:
        return None
    if name.type == "scope_resolution":  # Ruby: class Foo::Bar
        name = name.child_by_field_name("name") or name
    return _text(name) or None


def _go_receiver(node: ts.Node) -> str | None:
    """`func (s *Server) Get()` -> 'Server'."""
    receiver = node.child_by_field_name("receiver")
    if receiver is None:
        return None
    for n in _walk(receiver):
        if n.type == "type_identifier":
            return _text(n)
    return None


def _qualname(node: ts.Node, name: str, spec: LangSpec) -> str:
    parts = [name]
    if spec.name == "go" and node.type == "method_declaration" and (recv := _go_receiver(node)):
        parts.insert(0, recv)
    parent = node.parent
    while parent is not None:
        outer = _def_name(parent, spec)
        if outer:
            parts.insert(0, outer)
        parent = parent.parent
    return ".".join(parts)


def _start_line(node: ts.Node, spec: LangSpec) -> int:
    """Include decorators written just before the definition (TypeScript/JS)."""
    first = node
    prev = node.prev_named_sibling
    while prev is not None and prev.type in spec.decorators:
        first = prev
        prev = prev.prev_named_sibling
    return first.start_point[0] + 1


def definitions(tree: ts.Tree, spec: LangSpec) -> list[Definition]:
    found = []
    for node in _walk(tree.root_node):
        name = _def_name(node, spec)
        if not name:
            continue
        target = node
        if node.type == "variable_declarator":  # report the whole `const h = ...` statement
            target = node.parent if node.parent is not None else node
        found.append(Definition(
            name=name,
            qualname=_qualname(node, name, spec),
            kind=spec.defs[node.type],
            start=_start_line(target, spec),
            end=target.end_point[0] + 1,
            node=node,
        ))
    return found


def enclosing(node: ts.Node, spec: LangSpec) -> str:
    """Qualified name of the innermost function/method containing `node`.
    Unnamed callbacks (e.g. `it('...', () => {...})`) are reported as
    '<anonymous function in X>', where X is the nearest named scope."""
    anonymous = False
    parent = node.parent
    while parent is not None:
        name = _def_name(parent, spec)
        if name and spec.defs[parent.type] != "class":
            qual = _qualname(parent, name, spec)
            return f"<anonymous function in {qual}>" if anonymous else qual
        if not name and parent.type in spec.function_values and parent.parent is not None \
                and parent.parent.type != "variable_declarator":
            anonymous = True
        parent = parent.parent
    if anonymous:
        outer = "<top level>"
        parent = node.parent
        while parent is not None:
            name = _def_name(parent, spec)
            if name:
                outer = _qualname(parent, name, spec)
                break
            parent = parent.parent
        return f"<anonymous function in {outer}>"
    parent = node.parent  # not inside a function: report the class, if any
    while parent is not None:
        name = _def_name(parent, spec)
        if name:
            return _qualname(parent, name, spec)
        parent = parent.parent
    return "<top level>"


# References


def _callee_name(node: ts.Node, spec: LangSpec) -> str | None:
    """For a call node, the name being called: f(...) -> f, obj.f(...) -> f."""
    for fld in spec.calls.get(node.type, ()):
        callee = node.child_by_field_name(fld)
        if callee is None:
            continue
        if callee.type in spec.members:
            callee = callee.child_by_field_name(spec.members[callee.type])
        text = _text(callee)
        if text and text.replace("_", "").replace("$", "").isalnum():
            return text
    return None


def _is_ruby_bare_call(node: ts.Node, spec: LangSpec) -> bool:
    """Ruby lets you call a method with no receiver and no parentheses (`helper`),
    which parses as a plain identifier. Standing alone as a statement, it is
    almost always a call."""
    return (spec.name == "ruby" and node.type == "identifier" and node.parent is not None
            and node.parent.type in ("body_statement", "then", "else", "do", "begin", "program"))


def references(tree: ts.Tree, spec: LangSpec, name: str) -> list[tuple[int, str, str]]:
    """(line, kind, enclosing function) for every call to `name`."""
    hits = []
    for node in _walk(tree.root_node):
        if (node.type in spec.calls and _callee_name(node, spec) == name) or (
            _is_ruby_bare_call(node, spec) and _text(node) == name
        ):
            hits.append((node.start_point[0] + 1, "call", enclosing(node, spec)))
    return hits


# Routes


def _string_value(node: ts.Node, spec: LangSpec) -> str | None:
    if node.type not in spec.strings:
        return None
    return _text(node).strip("'\"`")


def _call_args(node: ts.Node) -> list[ts.Node]:
    args = node.child_by_field_name("arguments")
    return [a for a in args.named_children if a.type != "comment"] if args is not None else []


@dataclass
class RouterRoute:
    line: int
    method: str            # GET, POST, ... or ANY
    path: str              # e.g. "/users/:id"
    middleware: list[str]  # handlers registered before it in the same call

    @property
    def route(self) -> str:
        return f"{self.method} {self.path}"


@dataclass
class PathMiddleware:
    line: int
    path: str              # a prefix, e.g. "/rest/basket"
    middleware: list[str]  # e.g. ["security.isAuthorized()"]


def _handler_names(arg: ts.Node, spec: LangSpec, depth: int = 0) -> set[str]:
    """Names an argument can register as a handler: getUser, handlers.upload -> upload,
    login() -> login, and names inside wrappers such as asyncHandler(retrieveBasket())."""
    if arg.type in spec.calls:
        names = {n} if (n := _callee_name(arg, spec)) else set()
        if depth < 2:
            for inner in _call_args(arg):
                names |= _handler_names(inner, spec, depth + 1)
        return names
    text = _text(arg)
    return {text.rsplit(".", 1)[-1]} if text else set()


def _router_calls(tree: ts.Tree, spec: LangSpec):
    """(node, method name, path, handler-argument nodes) for every router-style call."""
    for node in _walk(tree.root_node):
        if node.type not in spec.calls:
            continue
        method = _callee_name(node, spec)
        if not method or method.lower() not in ROUTER_METHODS:
            continue
        args = _call_args(node)
        if len(args) < 2 or (path := _string_value(args[0], spec)) is None:
            continue
        yield node, method, path, args[1:]


def router_routes(tree: ts.Tree, spec: LangSpec, handler: str) -> list[RouterRoute]:
    """Router calls registering `handler` for a URL, e.g. app.get('/users/:id', auth, handler)
    (Express), app.post('/login', login()), or http.HandleFunc("/x", handler) (Go)."""
    found = []
    generic = ("use", "handle", "handlefunc", "route", "any", "all")
    for node, method, path, handler_args in _router_calls(tree, spec):
        if method.lower() == "use":
            continue  # app.use(...) mounts middleware or sub-routers, reported separately
        matches = [handler in _handler_names(a, spec) for a in handler_args]
        if not any(matches):
            continue
        first = matches.index(True)
        middleware = [_text(a) for a in handler_args[:first]]
        verb = "ANY" if method.lower() in generic else method.upper()
        found.append(RouterRoute(node.start_point[0] + 1, verb, path, middleware))
    return found


def path_middleware(tree: ts.Tree, spec: LangSpec) -> list[PathMiddleware]:
    """app.use('/prefix', mw1, mw2): middleware that runs for every route under the prefix."""
    return [
        PathMiddleware(node.start_point[0] + 1, path, [_text(a) for a in handler_args])
        for node, method, path, handler_args in _router_calls(tree, spec)
        if method.lower() == "use"
    ]


def covers(prefix: str, path: str) -> bool:
    """Does middleware mounted at `prefix` run for requests to `path`?"""
    prefix = prefix.rstrip("/")
    return prefix == "" or path == prefix or path.startswith(prefix + "/")


def _decorator_nodes(node: ts.Node, spec: LangSpec) -> list[ts.Node]:
    """Annotations/decorators attached to a definition, wherever the grammar puts them:
    Java inside `modifiers`; TypeScript as preceding siblings (methods), as children
    (classes), or on the surrounding `export` statement (exported classes)."""
    if spec.name == "java":
        mods = next((c for c in node.children if c.type == "modifiers"), None)
        return [c for c in mods.children if c.type in ("annotation", "marker_annotation")] if mods else []
    found = [c for c in node.children if c.type in spec.decorators]
    if node.parent is not None and node.parent.type == "export_statement":
        found = [c for c in node.parent.children if c.type in spec.decorators] + found
    prev = node.prev_named_sibling
    while prev is not None and prev.type in spec.decorators:
        found.insert(0, prev)
        prev = prev.prev_named_sibling
    return found


def _decorator_name_and_path(dec: ts.Node, spec: LangSpec) -> tuple[str, str | None]:
    """@GetMapping("/x") -> ("GetMapping", "/x"); @Get(':id') -> ("Get", ":id"); @Get -> ("Get", None)."""
    name_node = dec.child_by_field_name("name")  # Java
    args = dec.child_by_field_name("arguments")
    if name_node is None:  # TypeScript: @<identifier> or @<call_expression>
        inner = dec.named_children[0] if dec.named_children else None
        if inner is not None and inner.type == "call_expression":
            name_node, args = inner.child_by_field_name("function"), inner.child_by_field_name("arguments")
        else:
            name_node = inner
    path = None
    if args is not None:
        path = next((v for n in _walk(args) if (v := _string_value(n, spec)) is not None), None)
    return _text(name_node).rsplit(".", 1)[-1], path


def decorators_of(node: ts.Node, spec: LangSpec) -> list[str]:
    return [_text(d) for d in _decorator_nodes(node, spec)]


# Class-level annotations whose path prefixes every route in the class.
CLASS_ROUTE_PREFIXES = {"RequestMapping", "Controller"}


def _join(prefix: str, path: str) -> str:
    if not prefix:
        return path
    if not path:
        return prefix
    return f"{prefix.rstrip('/')}/{path.lstrip('/')}"


def annotation_routes(definition: Definition, spec: LangSpec) -> list[str]:
    """Routes declared by annotations/decorators on a method (Spring @GetMapping,
    NestJS @Get), with the enclosing class's path prefix (@RequestMapping("/api"),
    @Controller("users")) applied."""
    routes = []
    for dec in _decorator_nodes(definition.node, spec):
        name, path = _decorator_name_and_path(dec, spec)
        if name in ROUTE_ANNOTATIONS:
            routes.append((ROUTE_ANNOTATIONS[name], path or ""))
    if not routes:
        return []
    prefix = ""
    parent = definition.node.parent
    while parent is not None and parent.type not in ("class_declaration", "abstract_class_declaration"):
        parent = parent.parent
    if parent is not None:
        for dec in _decorator_nodes(parent, spec):
            name, path = _decorator_name_and_path(dec, spec)
            if name in CLASS_ROUTE_PREFIXES and path:
                prefix = path
                break
    return [f"{verb} {_join(prefix, path) or '/'}" for verb, path in routes]
