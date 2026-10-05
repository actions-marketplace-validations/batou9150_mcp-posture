"""Minimal MCP protocol prober over the hardened HTTP layer.

Era detection mirrors the official SDK: probe ``server/discover`` (2026-07-28 stateless
envelope); anything that is not a modern answer falls back to the ``initialize`` handshake
(≤ 2025-11-25); if the POST endpoint rejects that too, try the legacy HTTP+SSE GET stream.
Only list operations are sent; no tool is ever called.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Any

from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS, LATEST_HANDSHAKE_VERSION

from mcp_posture import __version__
from mcp_posture.context import Challenge, McpProbe, SurfaceItem, SurfaceKind, freeze
from mcp_posture.discovery import parse_www_authenticate
from mcp_posture.models import SpecRevision
from mcp_posture.net import Fetcher, HttpExchange, StopFn

MODERN_VERSION = SpecRevision.R2026_07_28.value
META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPS = "io.modelcontextprotocol/clientCapabilities"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
CLIENT_INFO = {"name": "mcp-posture", "version": __version__}
ACCEPT = "application/json, text/event-stream"
MAX_PAGES = 20
_IDENTITY: dict[str, str] = {
    "tool": "name",
    "prompt": "name",
    "resource": "uri",
    "resource_template": "uriTemplate",
}
SSE_READ_TIMEOUT = 5.0
SSE_FIELDS = (b"data:", b"event:", b"id:", b":", b"retry:")

LISTS: tuple[tuple[str, str, SurfaceKind, str], ...] = (
    ("tools/list", "tools", "tool", "tools"),
    ("prompts/list", "prompts", "prompt", "prompts"),
    ("resources/list", "resources", "resource", "resources"),
    ("resources/templates/list", "resourceTemplates", "resource_template", "resources"),
)


def parse_rpc_body(ex: HttpExchange, request_id: int | None = None) -> dict[str, Any] | None:
    """Extract the JSON-RPC response from a JSON or SSE body."""
    if ex.content_type == "text/event-stream":
        for data in iter_sse_data(ex.text):
            try:
                msg = json.loads(data)
            except (ValueError, RecursionError):
                continue
            if not isinstance(msg, dict) or not ("result" in msg or "error" in msg):
                continue
            if request_id is None or msg.get("id") == request_id:
                return dict(msg)
        return None
    doc = ex.json()
    return doc if isinstance(doc, dict) else None


def iter_sse_data(text: str) -> list[str]:
    events: list[str] = []
    data: list[str] = []
    for line in text.replace("\r\n", "\n").split("\n"):
        if line == "":
            if data:
                events.append("\n".join(data))
                data = []
        elif line.startswith("data:"):
            data.append(line[5:].removeprefix(" "))
    if data:
        events.append("\n".join(data))
    return events


def iter_sse_events(text: str) -> list[tuple[str, str]]:
    """(event, data) pairs; event defaults to ``message``."""
    out: list[tuple[str, str]] = []
    event, data = "message", list[str]()
    for line in text.replace("\r\n", "\n").split("\n"):
        if line == "":
            if data:
                out.append((event, "\n".join(data)))
            event, data = "message", []
        elif line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].removeprefix(" "))
    return out


def _sse_has_response(request_id: int) -> StopFn:
    """Stop reading an SSE body once the response to ``request_id`` has arrived.

    Stateful: each call parses only the events completed since the previous call, so a
    server trickling a large stream costs linear, not quadratic, time.
    """
    done = 0  # bytes of the buffer already parsed (always at an event boundary)

    def stop(buf: bytes) -> bool:
        nonlocal done
        if done == 0 and not buf[:64].lstrip().startswith(SSE_FIELDS):
            return False
        boundary = max(buf.rfind(b"\n\n") + 2, buf.rfind(b"\r\n\r\n") + 4, 0)
        if boundary <= done:
            return False
        events = buf[done:boundary].decode("utf-8", errors="ignore")
        done = boundary
        for data in iter_sse_data(events):
            try:
                msg = json.loads(data)
            except (ValueError, RecursionError):
                continue
            if isinstance(msg, dict) and msg.get("id") == request_id:
                return True
        return False

    return stop


def _endpoint_event(buf: bytes) -> bool:
    return b"event: endpoint" in buf or b"event:endpoint" in buf


@dataclass
class _State:
    """Mutable accumulator; frozen into :class:`McpProbe` at the end."""

    probe: McpProbe = field(default_factory=McpProbe)
    session_id: str | None = None
    version: str | None = None
    next_id: int = 1


class McpClient:
    def __init__(self, fetcher: Fetcher, url: str, token: str | None = None) -> None:
        self.fetcher = fetcher
        self.url = url
        self.token = token

    async def probe(self) -> McpProbe:
        st = _State()
        await self._run(st, authenticated=False)
        if st.probe.auth_required and self.token:
            st2 = _State(probe=st.probe)
            await self._run(st2, authenticated=True)
            st = st2
        return st.probe

    async def _run(self, st: _State, authenticated: bool) -> None:
        modern = await self._try_modern(st, authenticated)
        if modern is None:
            handshake = await self._try_handshake(st, authenticated)
            if handshake is None and not st.probe.auth_required:
                await self._try_legacy_sse(st, authenticated)
        if st.probe.era != "unknown" and not (st.probe.auth_required and not authenticated):
            await self._list_surface(st, authenticated)
        if st.session_id:
            await self._delete_session(st, authenticated)

    def _headers(self, st: _State, method: str, authenticated: bool) -> dict[str, str]:
        h = {"Accept": ACCEPT, "Content-Type": "application/json"}
        if st.version:
            h["MCP-Protocol-Version"] = st.version
        if st.probe.era == "modern" or method == "server/discover":
            h["Mcp-Method"] = method
        if st.session_id:
            h["Mcp-Session-Id"] = st.session_id
        if authenticated and self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    async def _rpc(
        self,
        st: _State,
        method: str,
        params: dict[str, Any] | None,
        authenticated: bool,
        *,
        notification: bool = False,
    ) -> tuple[HttpExchange, dict[str, Any] | None]:
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        rid = None
        if not notification:
            rid = st.next_id
            st.next_id += 1
            body["id"] = rid
        if params is not None:
            body["params"] = params
        ex = await self.fetcher.request(
            "POST",
            self.url,
            headers=self._headers(st, method, authenticated),
            json_body=body,
            follow_redirects=False,
            stop_when=_sse_has_response(rid) if rid is not None else None,
            read_timeout=SSE_READ_TIMEOUT,
        )
        if ex.status == 401:
            self._record_challenge(st, ex, authenticated)
        return ex, (parse_rpc_body(ex, rid) if rid is not None else None)

    def _record_challenge(self, st: _State, ex: HttpExchange, authenticated: bool) -> None:
        if authenticated:
            st.probe = replace(st.probe, token_rejected=True)
            return
        challenges: tuple[Challenge, ...] = parse_www_authenticate(
            ex.header_all("www-authenticate")
        )
        if not st.probe.auth_required:
            st.probe = replace(
                st.probe, auth_required=True, unauth_exchange=ex, challenges=challenges
            )

    def _modern_meta(self) -> dict[str, Any]:
        return {
            "_meta": {
                META_PROTOCOL_VERSION: MODERN_VERSION,
                META_CLIENT_INFO: CLIENT_INFO,
                META_CLIENT_CAPS: {},
            }
        }

    async def _try_modern(self, st: _State, authenticated: bool) -> bool | None:
        st.version = MODERN_VERSION
        ex, msg = await self._rpc(st, "server/discover", self._modern_meta(), authenticated)
        result = (msg or {}).get("result")
        if ex.status == 401:
            # Unknown era until authenticated; the handshake attempt below may tell us more.
            st.version = None
            return None
        if isinstance(result, dict) and MODERN_VERSION in (result.get("supportedVersions") or []):
            meta = result.get("_meta") or {}
            st.probe = replace(
                st.probe,
                transport="streamable-http",
                era="modern",
                negotiated_version=MODERN_VERSION,
                server_info=freeze(meta.get(META_SERVER_INFO)) if isinstance(meta, dict) else None,
            )
            sid = ex.header("mcp-session-id")
            if sid:
                st.probe = replace(st.probe, session_ids=(*st.probe.session_ids, sid))
            return True
        st.version = None
        return None

    async def _initialize(
        self, st: _State, authenticated: bool
    ) -> tuple[HttpExchange, dict[str, Any] | None]:
        params = {
            "protocolVersion": LATEST_HANDSHAKE_VERSION,
            "capabilities": {},
            "clientInfo": CLIENT_INFO,
        }
        return await self._rpc(st, "initialize", params, authenticated)

    async def _try_handshake(self, st: _State, authenticated: bool) -> bool | None:
        ex, msg = await self._initialize(st, authenticated)
        result = (msg or {}).get("result")
        if not isinstance(result, dict):
            return None
        version = result.get("protocolVersion")
        sid = ex.header("mcp-session-id")
        st.session_id = sid
        st.version = version if version in HANDSHAKE_PROTOCOL_VERSIONS else LATEST_HANDSHAKE_VERSION
        sids = (*st.probe.session_ids, sid) if sid else st.probe.session_ids
        st.probe = replace(
            st.probe,
            transport="streamable-http",
            era="handshake",
            negotiated_version=version if isinstance(version, str) else None,
            server_info=freeze(result.get("serverInfo")),
            session_ids=sids,
        )
        await self._rpc(st, "notifications/initialized", None, authenticated, notification=True)
        if sid and len(st.probe.session_ids) < 2:
            # A second session lets TRN08 compare identifiers; it is closed right away.
            second = _State(version=st.version, next_id=100)
            ex2, _ = await self._initialize(second, authenticated)
            sid2 = ex2.header("mcp-session-id")
            if sid2:
                st.probe = replace(st.probe, session_ids=(*st.probe.session_ids, sid2))
                second.session_id = sid2
                await self._delete_session(second, authenticated)
        return True

    async def _try_legacy_sse(self, st: _State, authenticated: bool) -> None:
        headers = {"Accept": "text/event-stream"}
        if authenticated and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        ex = await self.fetcher.request(
            "GET",
            self.url,
            headers=headers,
            follow_redirects=False,
            stop_when=_endpoint_event,
            read_timeout=SSE_READ_TIMEOUT,
            max_bytes=65_536,
        )
        if ex.status == 401:
            self._record_challenge(st, ex, authenticated)
            return
        if ex.content_type != "text/event-stream":
            return
        for event, data in iter_sse_events(ex.text + "\n\n"):
            if event == "endpoint":
                st.probe = replace(st.probe, transport="legacy-sse", legacy_endpoint=data.strip())
                return

    async def _list_surface(self, st: _State, authenticated: bool) -> None:
        items: list[SurfaceItem] = []
        errors: list[str] = list(st.probe.errors)
        listed = False
        for method, key, kind, _cap in LISTS:
            cursor: str | None = None
            for _ in range(MAX_PAGES):
                params: dict[str, Any] = self._modern_meta() if st.probe.era == "modern" else {}
                if cursor:
                    params["cursor"] = cursor
                ex, msg = await self._rpc(st, method, params or None, authenticated)
                result = (msg or {}).get("result")
                if not isinstance(result, dict):
                    if ex.status not in (None, 200) or (msg or {}).get("error"):
                        errors.append(f"{method}: HTTP {ex.status}")
                    break
                listed = True
                for raw in result.get(key) or []:
                    if isinstance(raw, dict):
                        # Resources are identified by URI; names may collide.
                        name = raw.get(_IDENTITY[kind]) or raw.get("name") or "?"
                        items.append(SurfaceItem(kind=kind, name=str(name), definition=freeze(raw)))
                cursor = result.get("nextCursor")
                if not isinstance(cursor, str) or not cursor:
                    break
        st.probe = replace(
            st.probe,
            surface=tuple(items),
            surface_listed=listed,
            surface_listed_unauthenticated=listed and not authenticated,
            errors=tuple(errors),
        )

    async def _delete_session(self, st: _State, authenticated: bool) -> None:
        headers = self._headers(st, "", authenticated)
        headers.pop("Content-Type", None)
        await self.fetcher.request("DELETE", self.url, headers=headers, follow_redirects=False)
