import sys
from pathlib import Path

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.memory import create_connected_server_and_client_session

from sast_triage.mcp_server import SERVER_NAME, build_server

DEMO_APP = Path(__file__).parent.parent / "examples" / "demo_app"
EXPECTED_TOOLS = {"list_files", "read_file", "search_code", "get_function", "find_references", "get_route_info"}


def _text(result) -> str:
    return "\n".join(c.text for c in result.content if c.type == "text")


def run_in_memory(check):
    """Connect an MCP client to a server for the demo app, in memory, and run `check`."""
    async def main():
        server = build_server(DEMO_APP)
        async with create_connected_server_and_client_session(server._mcp_server) as client:
            await check(client)

    anyio.run(main)


def test_lists_six_read_only_tools_with_descriptions():
    async def check(client: ClientSession):
        tools = (await client.list_tools()).tools
        assert {tool.name for tool in tools} == EXPECTED_TOOLS
        for tool in tools:
            assert tool.description, tool.name
            assert tool.annotations.readOnlyHint is True and tool.annotations.destructiveHint is False
        params = {tool.name: tool.inputSchema for tool in tools}
        assert params["find_references"]["required"] == ["name"]
        assert "description" in params["read_file"]["properties"]["path"]

    run_in_memory(check)


def test_server_instructions_warn_about_untrusted_content():
    async def main():
        server = build_server(DEMO_APP)
        async with create_connected_server_and_client_session(server._mcp_server) as client:
            info = await client.initialize()
            assert info.serverInfo.name == SERVER_NAME
            assert "untrusted" in info.instructions

    anyio.run(main)


def test_call_tools_fp01_investigation():
    """The two calls that settle FP-01, made through MCP."""
    async def check(client: ClientSession):
        refs = await client.call_tool("find_references", {"name": "get_user_by_id"})
        assert not refs.isError and "app.py:35 [call] in get_user" in _text(refs)
        fn = await client.call_tool("get_function", {"name": "get_user"})
        assert "uid = int(user_id)" in _text(fn)

    run_in_memory(check)


def test_bad_path_is_a_tool_error_not_a_crash():
    async def check(client: ClientSession):
        result = await client.call_tool("read_file", {"path": "../../etc/passwd"})
        assert result.isError and "outside the repository" in _text(result)
        # the server is still fine afterwards
        ok = await client.call_tool("list_files", {"pattern": "*.py"})
        assert not ok.isError and "app.py" in _text(ok)

    run_in_memory(check)


def test_invalid_arguments_are_rejected():
    async def check(client: ClientSession):
        result = await client.call_tool("read_file", {"path": "app.py", "start": 0})
        assert result.isError

    run_in_memory(check)


def test_stdio_end_to_end():
    """Start the real `sast-triage mcp-server` command as a subprocess and talk to it
    over stdio, the way Claude Desktop and our agent do. Any stray output on
    stdout would break the protocol and fail this test."""
    exe = Path(sys.executable).with_name("sast-triage")
    params = StdioServerParameters(command=str(exe), args=["mcp-server", str(DEMO_APP)])

    async def main():
        with anyio.fail_after(60):
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as client:
                    await client.initialize()
                    names = {tool.name for tool in (await client.list_tools()).tools}
                    assert names == EXPECTED_TOOLS
                    route = await client.call_tool("get_route_info", {"function": "get_user"})
                    assert "GET /users/<user_id>" in _text(route)

    anyio.run(main)
