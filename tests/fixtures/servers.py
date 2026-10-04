"""In-process fixture servers: a configurable MCP server emulator and authorization server.

Hostnames are routed in-process by :class:`Router`, so tests need no network. Every knob
defaults to the *secure* behaviour; misconfigured fixtures flip one knob at a time.
"""

from __future__ import annotations

import itertools
import json
import secrets
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response, StreamingResponse
from starlette.routing import Route

MCP_HOST = "mcp.test"
AS_HOST = "as.test"
MCP_URL = f"https://{MCP_HOST}/mcp"
ISSUER = f"https://{AS_HOST}"
PRM_URL = f"https://{MCP_HOST}/.well-known/oauth-protected-resource/mcp"
GOOD_TOKEN = "good-token-0123456789abcdef"

SAFE_TOOLS: list[dict[str, Any]] = [
    {
        "name": "get_weather",
        "description": "Return the current weather for a city.",
        "inputSchema": {
            "type": "object",
            "properties": {"city": {"type": "string", "maxLength": 80}},
            "required": ["city"],
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "delete_note",
        "description": "Delete one of the user's notes by id.",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "integer"}},
            "required": ["id"],
        },
        "annotations": {"destructiveHint": True, "readOnlyHint": False},
    },
]
SAFE_PROMPTS: list[dict[str, Any]] = [
    {"name": "summarize", "description": "Summarize a document.", "arguments": []}
]
SAFE_RESOURCES: list[dict[str, Any]] = [
    {"uri": "notes://all", "name": "notes", "description": "All notes.", "mimeType": "text/plain"}
]


def secure_prm() -> dict[str, Any]:
    return {
        "resource": MCP_URL,
        "authorization_servers": [ISSUER],
        "scopes_supported": ["mcp:tools", "mcp:read"],
        "bearer_methods_supported": ["header"],
        "resource_name": "Fixture MCP server",
    }


def secure_as_metadata(issuer: str = ISSUER) -> dict[str, Any]:
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{issuer}/jwks",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256", "RS256"],
        "scopes_supported": ["mcp:tools", "mcp:read"],
        "client_id_metadata_document_supported": True,
        "authorization_response_iss_parameter_supported": True,
    }


SECURE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}


def _uuid_sessions() -> Iterator[str]:
    while True:
        yield secrets.token_hex(16)


@dataclass
class McpProfile:
    """Behaviour of the emulated MCP server."""

    revision: str = "2026-07-28"  # "legacy-sse" for an SSE-only server
    path: str = "/mcp"
    tools: list[dict[str, Any]] = field(default_factory=lambda: list(SAFE_TOOLS))
    prompts: list[dict[str, Any]] = field(default_factory=lambda: list(SAFE_PROMPTS))
    resources: list[dict[str, Any]] = field(default_factory=lambda: list(SAFE_RESOURCES))
    page_size: int = 0  # >0 enables cursor pagination of tools
    require_auth: bool = True
    valid_tokens: frozenset[str] = frozenset({GOOD_TOKEN})
    challenge: str | None = f'Bearer resource_metadata="{PRM_URL}", scope="mcp:tools"'
    unauth_status: int = 401
    unauth_body: str = '{"error":"unauthorized"}'
    prm: dict[str, Any] | None = field(default_factory=secure_prm)
    prm_variants: frozenset[str] = frozenset({"path-insertion"})
    prm_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
    prm_content_type: str = "application/json"
    sessions: Callable[[], Iterator[str]] | None = _uuid_sessions
    headers: dict[str, str] = field(default_factory=lambda: dict(SECURE_HEADERS))
    not_found_body: str = '{"error":"not found"}'
    sse_responses: bool = False
    legacy_endpoint: str = "/messages?sessionId=abc"
    modern_session_header: bool = False
    authorization_server_paths: bool = False  # 2025-03-26: /authorize etc. on the MCP origin
    legacy_as_metadata: dict[str, Any] | None = None


@dataclass
class AsProfile:
    issuer: str = ISSUER
    metadata: dict[str, Any] | None = field(default_factory=secure_as_metadata)
    variant: str = "rfc8414"  # rfc8414 | oidc-insert | oidc-append
    headers: dict[str, str] = field(default_factory=lambda: dict(SECURE_HEADERS))


def _json(data: Any, status: int = 200, headers: dict[str, str] | None = None) -> Response:
    return Response(
        json.dumps(data), status_code=status, media_type="application/json", headers=headers
    )


def mcp_app(profile: McpProfile) -> Starlette:
    session_source = profile.sessions() if profile.sessions else None
    live_sessions: set[str] = set()

    def authorized(request: Request) -> bool:
        if not profile.require_auth:
            return True
        auth = request.headers.get("authorization", "")
        return auth.startswith("Bearer ") and auth[7:] in profile.valid_tokens

    def deny(request: Request) -> Response:
        headers = dict(profile.headers)
        if profile.challenge is not None:
            has_token = request.headers.get("authorization", "").startswith("Bearer ")
            value = profile.challenge
            if has_token:
                value += ', error="invalid_token"'
            headers["WWW-Authenticate"] = value
        return Response(
            profile.unauth_body,
            status_code=profile.unauth_status,
            media_type="application/json",
            headers=headers,
        )

    def respond(request: Request, payload: dict[str, Any], extra: dict[str, str]) -> Response:
        headers = {**profile.headers, **extra}
        if profile.sse_responses:
            body = f"event: message\ndata: {json.dumps(payload)}\n\n"
            return Response(body, media_type="text/event-stream", headers=headers)
        return _json(payload, headers=headers)

    def list_result(method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "tools/list":
            items, key = profile.tools, "tools"
        elif method == "prompts/list":
            items, key = profile.prompts, "prompts"
        elif method == "resources/list":
            items, key = profile.resources, "resources"
        else:
            items, key = [], "resourceTemplates"
        if profile.page_size and key == "tools":
            start = int(params.get("cursor") or 0)
            page = items[start : start + profile.page_size]
            out: dict[str, Any] = {key: page}
            if start + profile.page_size < len(items):
                out["nextCursor"] = str(start + profile.page_size)
            return out
        return {key: items}

    async def post(request: Request) -> Response:
        if profile.revision == "legacy-sse":
            return PlainTextResponse("Method Not Allowed", status_code=405)
        if not authorized(request):
            return deny(request)
        try:
            msg = json.loads(await request.body())
        except ValueError:
            return _json({"jsonrpc": "2.0", "id": None, "error": {"code": -32700}}, 400)
        method = msg.get("method")
        rid = msg.get("id")
        params = msg.get("params") or {}
        modern = profile.revision == "2026-07-28"
        if rid is None:
            return Response(status_code=202)
        if method == "server/discover":
            if not modern:
                return _json(
                    {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "nf"}},
                    404 if profile.revision == "2025-11-25" else 200,
                )
            result = {
                "supportedVersions": ["2026-07-28"],
                "capabilities": {"tools": {}, "prompts": {}, "resources": {}},
                "_meta": {
                    "io.modelcontextprotocol/serverInfo": {"name": "fixture", "version": "1"}
                },
            }
            extra_modern = (
                {"Mcp-Session-Id": "leftover-session"} if profile.modern_session_header else {}
            )
            return respond(request, {"jsonrpc": "2.0", "id": rid, "result": result}, extra_modern)
        if method == "initialize":
            if modern:
                return _json(
                    {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "nf"}}, 404
                )
            extra: dict[str, str] = {}
            if session_source is not None:
                sid = next(session_source)
                live_sessions.add(sid)
                extra["Mcp-Session-Id"] = sid
            result = {
                "protocolVersion": profile.revision,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fixture", "version": "1"},
            }
            return respond(request, {"jsonrpc": "2.0", "id": rid, "result": result}, extra)
        if method in ("tools/list", "prompts/list", "resources/list", "resources/templates/list"):
            result = list_result(method, params)
            return respond(request, {"jsonrpc": "2.0", "id": rid, "result": result}, {})
        return _json({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "nf"}})

    async def get(request: Request) -> Response:
        if profile.revision != "legacy-sse":
            return PlainTextResponse("Method Not Allowed", status_code=405)
        if not authorized(request):
            return deny(request)

        async def stream() -> Any:
            yield f"event: endpoint\ndata: {profile.legacy_endpoint}\n\n".encode()

        return StreamingResponse(stream(), media_type="text/event-stream")

    async def delete(request: Request) -> Response:
        sid = request.headers.get("mcp-session-id")
        if sid:
            live_sessions.discard(sid)
        return Response(status_code=204)

    async def endpoint(request: Request) -> Response:
        if request.method == "POST":
            return await post(request)
        if request.method == "GET":
            return await get(request)
        return await delete(request)

    def prm_route(variant: str) -> Callable[[Request], Any]:
        async def handler(request: Request) -> Response:
            if profile.prm is None or variant not in profile.prm_variants:
                return _json({"error": "not found"}, 404, profile.headers)
            doc = {**profile.prm, **profile.prm_overrides.get(variant, {})}
            return Response(
                json.dumps(doc),
                media_type=profile.prm_content_type,
                headers=profile.headers,
            )

        return handler

    async def legacy_as(request: Request) -> Response:
        if profile.legacy_as_metadata is None:
            return _json({"error": "not found"}, 404)
        return _json(profile.legacy_as_metadata, headers=profile.headers)

    async def default_endpoint(request: Request) -> Response:
        if not profile.authorization_server_paths:
            return _json({"error": "not found"}, 404)
        return PlainTextResponse("login", status_code=200)

    async def not_found(request: Request) -> Response:
        return Response(profile.not_found_body, status_code=404, headers=profile.headers)

    routes = [
        Route(profile.path, endpoint, methods=["GET", "POST", "DELETE"]),
        Route(
            f"/.well-known/oauth-protected-resource{profile.path}",
            prm_route("path-insertion"),
        ),
        Route("/.well-known/oauth-protected-resource", prm_route("root")),
        Route("/.well-known/custom-prm", prm_route("custom")),
        Route("/.well-known/oauth-authorization-server", legacy_as),
        Route("/authorize", default_endpoint),
        Route("/token", default_endpoint),
        Route("/register", default_endpoint),
        Route("/{path:path}", not_found),
    ]
    return Starlette(routes=routes)


def as_app(profile: AsProfile) -> Starlette:
    issuer_path = urlsplit(profile.issuer).path.rstrip("/")
    paths = {
        "rfc8414": f"/.well-known/oauth-authorization-server{issuer_path}",
        "oidc-insert": f"/.well-known/openid-configuration{issuer_path}",
        "oidc-append": f"{issuer_path}/.well-known/openid-configuration",
    }

    async def metadata(request: Request) -> Response:
        if profile.metadata is None:
            return _json({"error": "not found"}, 404)
        return _json(profile.metadata, headers=profile.headers)

    async def not_found(request: Request) -> Response:
        return _json({"error": "not found"}, 404)

    return Starlette(
        routes=[Route(paths[profile.variant], metadata), Route("/{path:path}", not_found)]
    )


class Router(httpx.AsyncBaseTransport):
    """Routes requests to in-process ASGI apps by (scheme, host); unknown hosts refuse."""

    def __init__(self, apps: dict[str, Any]) -> None:
        self._transports = {k: httpx.ASGITransport(app=v) for k, v in apps.items()}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        key = f"{request.url.scheme}://{request.url.host}"
        transport = self._transports.get(key) or self._transports.get(request.url.host)
        if transport is None:
            raise httpx.ConnectError(f"connection refused: {key}", request=request)
        return await transport.handle_async_request(request)


def router(
    mcp: McpProfile | None = None,
    auth: AsProfile | None = None,
    *,
    http_listener: bool = False,
    extra: dict[str, Any] | None = None,
) -> Callable[[], Router]:
    """Transport factory for ScanOptions: a fresh app instance per target scan."""
    mcp = mcp or McpProfile()
    auth = auth or AsProfile()

    def factory() -> Router:
        app = mcp_app(mcp)
        apps: dict[str, Any] = {
            f"https://{MCP_HOST}": app,
            f"https://{urlsplit(auth.issuer).hostname}": as_app(auth),
            **(extra or {}),
        }
        if http_listener:
            apps[f"http://{MCP_HOST}"] = app
        return Router(apps)

    return factory


def counter_sessions(start: int = 1000) -> Callable[[], Iterator[str]]:
    return lambda: (str(i) for i in itertools.count(start))


def static_sessions(value: str) -> Callable[[], Iterator[str]]:
    return lambda: itertools.repeat(value)
