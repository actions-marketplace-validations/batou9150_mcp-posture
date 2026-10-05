from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator

import httpx
import pytest
from mcp.server.mcpserver import MCPServer
from starlette.applications import Starlette

from mcp_posture.client import McpClient, iter_sse_data, iter_sse_events, parse_rpc_body
from mcp_posture.context import McpProbe
from mcp_posture.models import SpecRevision
from mcp_posture.net import Fetcher, HttpExchange, NetSettings
from tests.conftest import run_scan
from tests.fixtures.servers import GOOD_TOKEN, MCP_URL, SAFE_TOOLS, McpProfile, Router, mcp_app


async def probe(profile: McpProfile, token: str | None = None) -> McpProbe:
    async with Fetcher(
        NetSettings(retries=0), transport=Router({"mcp.test": mcp_app(profile)})
    ) as f:
        return await McpClient(f, MCP_URL, token).probe()


def test_modern_server() -> None:
    p = asyncio.run(probe(McpProfile(require_auth=False)))
    assert (p.era, p.transport, p.negotiated_version) == ("modern", "streamable-http", "2026-07-28")
    assert p.server_info is not None and p.server_info["name"] == "fixture"
    assert [i.location for i in p.surface] == [
        "tool:get_weather",
        "tool:delete_note",
        "prompt:summarize",
        "resource:notes://all",
    ]
    assert p.surface_listed_unauthenticated


@pytest.mark.parametrize("revision", ["2025-03-26", "2025-06-18", "2025-11-25"])
def test_handshake_servers(revision: str) -> None:
    p = asyncio.run(probe(McpProfile(revision=revision, require_auth=False)))
    assert (p.era, p.negotiated_version) == ("handshake", revision)
    assert len(p.session_ids) == 2 and p.session_ids[0] != p.session_ids[1]


def test_sse_responses_and_pagination() -> None:
    tools = [{**SAFE_TOOLS[0], "name": f"t{i}"} for i in range(5)]
    profile = McpProfile(require_auth=False, sse_responses=True, page_size=2, tools=tools)
    p = asyncio.run(probe(profile))
    assert [i.name for i in p.surface if i.kind == "tool"] == ["t0", "t1", "t2", "t3", "t4"]


def test_auth_flow_with_valid_and_invalid_token() -> None:
    anon = asyncio.run(probe(McpProfile()))
    assert anon.auth_required and not anon.surface_listed and anon.era == "unknown"
    assert anon.challenges[0].get("resource_metadata")
    good = asyncio.run(probe(McpProfile(revision="2025-06-18"), token=GOOD_TOKEN))
    assert good.surface_listed and not good.surface_listed_unauthenticated
    assert good.negotiated_version == "2025-06-18" and not good.token_rejected
    bad = asyncio.run(probe(McpProfile(), token="wrong-token-value"))
    assert bad.token_rejected and not bad.surface_listed


def test_scan_with_token_negotiates_revision() -> None:
    result = run_scan(McpProfile(revision="2025-06-18"), token=GOOD_TOKEN)
    assert result.spec_revision == SpecRevision.R2025_06_18
    assert result.revision_source == "negotiated"


def test_sse_helpers() -> None:
    text = "event: endpoint\ndata: /m\n\ndata: a\ndata: b\n\n: comment\n"
    assert iter_sse_events(text) == [("endpoint", "/m"), ("message", "a\nb")]
    assert iter_sse_data("data: x\r\n\r\ndata: y") == ["x", "y"]
    sse = HttpExchange(
        "POST",
        "u",
        status=200,
        headers=(("content-type", "text/event-stream"),),
        body=b'data: not json\n\ndata: {"jsonrpc":"2.0","id":9,"result":{}}\n\n'
        b'data: {"jsonrpc":"2.0","id":1,"result":{"ok":1}}\n\n',
    )
    assert parse_rpc_body(sse, 1) == {"jsonrpc": "2.0", "id": 1, "result": {"ok": 1}}
    assert parse_rpc_body(sse, 2) is None
    not_rpc = HttpExchange("POST", "u", status=200, body=b"[1]")
    assert parse_rpc_body(not_rpc, 1) is None


@contextlib.asynccontextmanager
async def _official(stateless: bool) -> AsyncIterator[Starlette]:
    server = MCPServer("official")

    @server.tool()
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b

    app = server.streamable_http_app(stateless_http=stateless, host="mcp.test")
    async with app.router.lifespan_context(app):
        yield app


@pytest.mark.parametrize("stateless", [False, True])
def test_interop_with_official_sdk_server(stateless: bool) -> None:
    """The prober must understand the reference implementation, both modes, SSE replies."""

    async def go() -> McpProbe:
        async with _official(stateless) as app:
            transport = Router({"mcp.test": app})
            async with Fetcher(NetSettings(retries=0), transport=transport) as f:
                return await McpClient(f, MCP_URL).probe()

    p = asyncio.run(go())
    assert p.era == "modern" and p.negotiated_version == "2026-07-28"
    assert [i.name for i in p.surface] == ["add"]


def test_unreachable_target() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    result = run_scan(transport=lambda: httpx.MockTransport(refuse))  # type: ignore[arg-type,return-value]
    assert not result.reachable and "refused" in (result.error or "")


def test_non_mcp_endpoint_is_reachable_but_unknown() -> None:
    def html(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html="<html>hello</html>")

    result = run_scan(transport=lambda: httpx.MockTransport(html))  # type: ignore[arg-type,return-value]
    assert result.reachable and result.transport == "unknown"


def test_sse_stop_condition_parses_each_event_once() -> None:
    from mcp_posture.client import _sse_has_response

    stop = _sse_has_response(7)
    noise = b'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/progress"}\n\n'
    buf = b""
    for _ in range(50):
        buf += noise
        assert not stop(buf)
    buf += b'data: {"jsonrpc":"2.0","id":7,'
    assert not stop(buf)  # incomplete event
    buf += b'"result":{}}\r\n\r\n'
    assert stop(buf)
    assert not _sse_has_response(1)(b'{"jsonrpc":"2.0","id":1,"result":{}}\n\n')  # not SSE
