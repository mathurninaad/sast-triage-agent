"""Multi-language structure tools (tree-sitter), on tests/fixtures/polyglot:
one small app each in JavaScript (Express), TypeScript (NestJS), Java
(Spring), Go (net/http) and Ruby (Rails-style)."""

from pathlib import Path

import pytest

from sast_triage.context import tools as t
from sast_triage.context import treesitter as tsx
from sast_triage.context.repo import Repo, RepoError

POLYGLOT = Path(__file__).parent / "fixtures" / "polyglot"


@pytest.fixture
def repo():
    return Repo(POLYGLOT)


def test_language_detection():
    assert tsx.spec_for(Path("a.tsx")).name == "tsx"
    assert tsx.spec_for(Path("A.java")).name == "java"
    assert tsx.spec_for(Path("a.py")) is None  # Python is handled by the ast module
    assert tsx.spec_for(Path("a.php")) is None


def test_find_references_across_languages(repo):
    js_ts_java = t.find_references(repo, "findUser")
    assert "server.js:11 [call] in getUser" in js_ts_java
    assert "users.controller.ts:10 [call] in UsersController.findOne" in js_ts_java
    assert "UserController.java:12 [call] in UserController.show" in js_ts_java
    assert "main.go:8 [call] in Server.GetUser" in t.find_references(repo, "FindUser")
    assert "users_controller.rb:5 [call] in UsersController.show" in t.find_references(repo, "find_user")


def test_comments_and_strings_are_not_calls(repo):
    out = t.find_references(repo, "findUser")
    assert out.startswith("3 references")           # server.js:7-8 and Java:11 mention it in text only
    assert "server.js:7" not in out and "server.js:8" not in out and "UserController.java:11" not in out


def test_ruby_call_without_parentheses(repo):
    assert "users_controller.rb:6 [call] in UsersController.show: audit_access" in t.find_references(repo, "audit_access")


def test_get_function_includes_decorators_and_annotations(repo):
    ts_out = t.get_function(repo, "UsersController.findOne")
    assert "users.controller.ts:7-11" in ts_out and '@Get(":id")' in ts_out and "@UseGuards(AuthGuard)" in ts_out
    java = t.get_function(repo, "show", file="UserController.java")
    assert "UserController.java:8-13 (UserController.show)" in java and "@PreAuthorize" in java


def test_get_function_arrow_function_and_go_method(repo):
    assert "server.js:10-12 (getUser)" in t.get_function(repo, "getUser")
    assert "main.go:7-9 (Server.GetUser)" in t.get_function(repo, "Server.GetUser")
    assert "Server.GetUser" in t.get_function(repo, "GetUser")  # plain name works too


def test_routes_express_with_middleware(repo):
    out = t.get_route_info(repo, "getUser")
    assert "server.js:14: GET /users/:id (middleware before it: requireLogin)" in out
    assert "looks like an access check: requireLogin" in out
    assert "server.js:15: POST /upload" in t.get_route_info(repo, "upload")  # obj.handler form


def test_routes_nestjs_with_controller_prefix(repo):
    out = t.get_route_info(repo, "findOne")
    assert "routes: GET users/:id" in out
    assert "looks like an access check: @UseGuards(AuthGuard)" in out


def test_routes_spring_with_class_prefix(repo):
    out = t.get_route_info(repo, "show", file="UserController.java")
    assert "routes: GET /api/users/{id}" in out
    assert "access check: @PreAuthorize" in out


def test_routes_go_net_http(repo):
    assert "main.go:13: ANY /users" in t.get_route_info(repo, "GetUser")


def test_structural_tools_refuse_unsupported_files(repo, tmp_path):
    (tmp_path / "notes.txt").write_text("hello")
    with pytest.raises(RepoError, match="read_file or search_code"):
        t.get_function(Repo(tmp_path), "x", file="notes.txt")


def test_broken_code_still_parses(tmp_path):
    """tree-sitter is error-tolerant: a syntax error elsewhere doesn't hide valid code."""
    (tmp_path / "app.js").write_text("function ok() { save(1); }\nfunction broken( {\n")
    out = t.find_references(Repo(tmp_path), "save")
    assert "app.js:1 [call] in ok" in out


def test_python_still_uses_ast():
    demo = Repo(Path(__file__).parent.parent / "examples" / "demo_app")
    assert "app.py:35 [call] in get_user" in t.find_references(demo, "get_user_by_id")


def test_routes_factory_handlers_and_middleware(tmp_path):
    """Real Express apps often register the result of a call: app.post('/login', login())."""
    (tmp_path / "server.ts").write_text(
        "app.post('/rest/user/login', login())\n"
        "app.get('/rest/basket/:id', security.isAuthorized(), retrieveBasket())\n"
        "app.put('/rest/basket/:id/coupon', utils.asyncHandler(applyCoupon()))\n"
    )
    (tmp_path / "routes.ts").write_text("export function login () { return 1 }\nexport function retrieveBasket () { return 2 }\nexport function applyCoupon () { return 3 }\n")
    repo = Repo(tmp_path)
    assert "server.ts:1: POST /rest/user/login" in t.get_route_info(repo, "login")
    basket = t.get_route_info(repo, "retrieveBasket")
    assert "server.ts:2: GET /rest/basket/:id (middleware before it: security.isAuthorized())" in basket
    assert "looks like an access check: security.isAuthorized()" in basket
    # handler wrapped in another call
    assert "server.ts:3: PUT /rest/basket/:id/coupon" in t.get_route_info(repo, "applyCoupon")


def test_path_level_middleware_applies_to_routes_under_it(tmp_path):
    """app.use('/rest/basket', auth) protects every route under /rest/basket, even
    though the route line itself shows no middleware."""
    (tmp_path / "server.js").write_text(
        "app.use('/rest/basket', security.isAuthorized(), security.appendUserId())\n"
        "app.use('/api', rateLimit())\n"
        "app.get('/rest/basket/:id', retrieveBasket())\n"
        "app.get('/rest/basketball', listBalls)\n"
    )
    repo = Repo(tmp_path)
    basket = t.get_route_info(repo, "retrieveBasket")
    assert "also runs app.use middleware for /rest/basket (server.js:1)" in basket
    assert "looks like an access check: security.isAuthorized()" in basket
    assert "/api" not in basket                      # different prefix
    balls = t.get_route_info(repo, "listBalls")
    assert "app.use" not in balls                    # /rest/basketball is not under /rest/basket
    assert tsx.covers("", "/anything") and tsx.covers("/a", "/a") and not tsx.covers("/a", "/ab")


def test_calls_in_anonymous_callbacks(tmp_path):
    (tmp_path / "a.spec.js").write_text("describe('x', () => {\n  it('y', () => { login() })\n})\n")
    assert "[call] in <anonymous function in <top level>>" in t.find_references(Repo(tmp_path), "login")
