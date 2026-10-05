"""Interactive OAuth login to an MCP server the operator owns.

The flow an MCP client runs: 401 challenge, Protected Resource Metadata, authorization server
metadata, client identity (pre-registered, Client ID Metadata Document, or Dynamic Client
Registration), authorization code with PKCE S256 caught on a loopback listener, and a token
exchange bound to the resource (RFC 8707). Every URL comes from the server and is treated as
hostile: all requests go through the hardened :class:`~mcp_posture.net.Fetcher`, and the only
URL ever opened in the operator's browser is the advertised authorization endpoint.

The token is returned to the caller and never logged; refresh tokens are discarded.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import inspect
import json
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import parse_qs, quote, urlencode, urlsplit

import httpx

from mcp_posture import __version__
from mcp_posture.cimd_lint import LintInput, lint, parse_document
from mcp_posture.client import McpClient, same_origin
from mcp_posture.context import AuthDiscovery, thaw
from mcp_posture.discovery import bearer_challenge, discover_auth, well_known_root
from mcp_posture.models import Severity
from mcp_posture.net import Fetcher, HttpExchange, NetSettings, is_loopback_host
from mcp_posture.redact import Redactor
from mcp_posture.report import neutralize

CALLBACK_PATH = "/callback"
# mcp-posture's own Client ID Metadata Document, published with the docs (docs/oauth/client.json).
# Used when the authorization server supports CIMD and no other client identity is given, as
# MCP clients do; it lists the loopback redirect and no secret.
DEFAULT_CLIENT_METADATA_URL = "https://batou9150.github.io/mcp-posture/oauth/client.json"
LOOPBACK = "127.0.0.1"
MAX_REQUEST_HEAD = 8192
MAX_CALLBACK_CONNECTIONS = 16
HEAD_READ_TIMEOUT = 5.0
CIMD_FETCH_LIMIT = 64 * 1024
Strategy = Literal["pre-registered", "cimd", "dcr"]


class LoginError(Exception):
    """The flow failed (refused, denied, timed out, or an AS error)."""

    def __init__(self, message: str, *, unreachable: bool = False) -> None:
        super().__init__(message)
        self.unreachable = unreachable


class LoginNotRequired(Exception):
    """The server answered without asking for authentication."""


@dataclass(frozen=True)
class LoginOptions:
    client_id: str | None = None
    client_secret: str | None = field(default=None, repr=False)
    client_metadata_url: str | None = None
    register: bool | None = None  # None: ask when interactive, refuse otherwise
    keep_client: bool = False
    scope: str | None = None
    port: int = 0
    open_browser: bool = True
    timeout: float = 300.0
    authorization_server: str | None = None
    default_client: bool = True  # use mcp-posture's own CIMD document when the AS supports CIMD


@dataclass
class LoginUI:
    """How the flow talks to the operator. Messages go to stderr in the CLI."""

    say: Callable[[str], None]
    open_url: Callable[[str], object]  # returns False when no browser; may be async (tests)
    confirm: Callable[[str], bool] | None = None  # None: non-interactive


@dataclass(frozen=True)
class LoginResult:
    access_token: str = field(repr=False)
    token_type: str
    scope: str | None
    expires_in: int | None
    client_id: str
    strategy: Strategy
    issuer: str
    resource: str
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Server:
    """What the flow needs from discovery, validated."""

    issuer: str
    resource: str
    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: str | None
    s256: bool | None  # None: unknown (2025-03-26 default endpoints, no metadata)
    cimd: bool
    iss_supported: bool
    auth_methods: tuple[str, ...]
    grant_types: tuple[str, ...]
    scope: str | None


def _text(value: object, limit: int = 200) -> str:
    """Server-controlled text for a terminal message."""
    return neutralize(str(value), json_escapes=False)[:limit]


def _vet_endpoint(name: str, url: object, net: NetSettings) -> str:
    if not isinstance(url, str) or not url:
        raise LoginError(f"the authorization server metadata has no {name}")
    if any(c.isspace() or ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in url):
        raise LoginError(f"{name} contains whitespace or control characters; refusing to use it")
    p = urlsplit(url)
    if p.scheme == "https" and p.hostname:
        return url
    if p.scheme == "http" and p.hostname and is_loopback_host(p.hostname) and net.allow_private:
        return url
    raise LoginError(f"{name} {_text(url)!r} is not an https URL; refusing to use it")


# Identity providers that answer with the long form of OIDC's short scopes (Google does).
_SCOPE_ALIASES = {
    "https://www.googleapis.com/auth/userinfo.email": "email",
    "https://www.googleapis.com/auth/userinfo.profile": "profile",
}


def _scopes(scope: str) -> set[str]:
    return {_SCOPE_ALIASES.get(s, s) for s in scope.split()}


def _without_offline_access(scope: str | None) -> str | None:
    """Login never asks for refresh tokens it would discard (MCP 2026-07-28 PRM guidance)."""
    if scope is None:
        return None
    kept = [s for s in scope.split() if s != "offline_access"]
    return " ".join(kept) or None


def _str_list(value: object) -> tuple[str, ...]:
    if isinstance(value, list | tuple):
        return tuple(v for v in value if isinstance(v, str))
    return ()


async def _discover(fetcher: Fetcher, url: str, opts: LoginOptions, net: NetSettings) -> _Server:
    probe = await McpClient(fetcher, url).probe()
    if not any(ex.status is not None for ex in fetcher.log):
        first = fetcher.log[0] if fetcher.log else None
        raise LoginError(
            f"cannot reach {url}: {first.error if first and first.error else 'no response'}",
            unreachable=True,
        )
    if not probe.auth_required:
        raise LoginNotRequired
    bearer = bearer_challenge(probe.challenges)
    if bearer is None:
        raise LoginError("the server answers 401 without a Bearer challenge")
    auth: AuthDiscovery = await discover_auth(
        fetcher, url, bearer.get("resource_metadata"), legacy_origin_as=True
    )
    challenge_scope = bearer.get("scope")

    prm = auth.prm
    if prm is not None and prm.document is not None:
        doc = thaw(prm.document)
        resource = doc.get("resource")
        allowed = {url}
        if prm.variant == "root":
            p = urlsplit(url)
            allowed |= {f"{p.scheme}://{p.netloc}", f"{p.scheme}://{p.netloc}/"}
        if not isinstance(resource, str) or resource not in allowed:
            raise LoginError(
                f"Protected Resource Metadata resource {_text(resource)!r} does not match "
                f"{url!r}; a token for it would not be meant for this server"
            )
        servers = auth.authorization_servers
        if not servers:
            raise LoginError("Protected Resource Metadata lists no authorization server")
        chosen = servers[0]
        if opts.authorization_server is not None:
            match = [s for s in servers if s.issuer == opts.authorization_server]
            if not match:
                listed = ", ".join(s.issuer for s in servers)
                raise LoginError(f"--authorization-server must be one of: {listed}")
            chosen = match[0]
        _vet_endpoint("issuer", chosen.issuer, net)  # RFC 8414: https, before trusting its metadata
        meta = thaw(chosen.document) if chosen.document is not None else None
        if meta is None:
            raise LoginError(f"no authorization server metadata found for {chosen.issuer}")
        if meta.get("issuer") != chosen.issuer:
            raise LoginError(
                f"authorization server metadata declares issuer {_text(meta.get('issuer'))!r}, "
                f"expected {chosen.issuer!r}"
            )
        issuer = chosen.issuer
        default_endpoints = False
        scopes = [s for s in _str_list(doc.get("scopes_supported")) if s != "offline_access"]
        default_scope = challenge_scope or (" ".join(scopes) if scopes else None)
    elif auth.legacy_as is not None:
        # MCP 2025-03-26: the MCP server is the authorization server, at its origin.
        resource = url
        issuer = auth.legacy_as.issuer
        meta = thaw(auth.legacy_as.document) if auth.legacy_as.document is not None else None
        if meta is not None and str(meta.get("issuer", "")).rstrip("/") != issuer.rstrip("/"):
            raise LoginError(f"metadata issuer {_text(meta.get('issuer'))!r} != {issuer!r}")
        default_endpoints = meta is None
        if meta is None:
            meta = {
                "authorization_endpoint": well_known_root(url, "/authorize"),
                "token_endpoint": well_known_root(url, "/token"),
                "registration_endpoint": well_known_root(url, "/register"),
            }
        default_scope = challenge_scope
        _vet_endpoint("issuer", issuer, net)
    else:  # pragma: no cover - discover_auth always yields one of the two above
        raise LoginError("no authorization metadata found")

    if opts.client_secret and opts.authorization_server != issuer:
        # The server under test chooses the AS; never hand a confidential client's secret to
        # an AS the operator did not name.
        raise LoginError(
            f"a client secret is only sent to an authorization server you name: pass "
            f"--authorization-server {issuer} if that is the one the secret belongs to"
        )
    s256: bool | None
    if "code_challenge_methods_supported" in meta:
        s256 = "S256" in _str_list(meta["code_challenge_methods_supported"])
    elif default_endpoints:
        s256 = None  # 2025-03-26 default endpoints: nothing advertised, PKCE used anyway
    else:
        s256 = False  # MCP: clients MUST refuse when the field is absent
    if s256 is False:
        raise LoginError(
            "the authorization server does not advertise PKCE S256; MCP clients must refuse it"
        )
    registration = meta.get("registration_endpoint")
    return _Server(
        issuer=issuer,
        resource=str(resource),
        authorization_endpoint=_vet_endpoint(
            "authorization_endpoint", meta.get("authorization_endpoint"), net
        ),
        token_endpoint=_vet_endpoint("token_endpoint", meta.get("token_endpoint"), net),
        registration_endpoint=(
            _vet_endpoint("registration_endpoint", registration, net)
            if isinstance(registration, str)
            else None
        ),
        s256=s256,
        cimd=meta.get("client_id_metadata_document_supported") is True,
        iss_supported=meta.get("authorization_response_iss_parameter_supported") is True,
        auth_methods=_str_list(meta.get("token_endpoint_auth_methods_supported")),
        grant_types=_str_list(meta.get("grant_types_supported")),
        scope=opts.scope or _without_offline_access(default_scope),
    )


# --- loopback callback -------------------------------------------------------------------

_PAGE = (
    "<!doctype html><meta charset=utf-8><title>mcp-posture</title>"
    "<p style='font:16px system-ui;margin:3em'>{}</p>"
)
_SECURITY_HEADERS = (
    "Content-Type: text/html; charset=utf-8\r\n"
    "Cache-Control: no-store\r\n"
    "Referrer-Policy: no-referrer\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\n"
    "Connection: close\r\n"
)


class CallbackServer:
    """Single-use HTTP listener on 127.0.0.1 for the authorization response.

    Only ``GET /callback`` carrying the expected ``state`` completes the flow; anything else
    gets a static error page and is ignored. Nothing from the request is echoed back.
    """

    def __init__(self, state: str, port: int = 0) -> None:
        self._state = state
        self._port = port
        self._server: asyncio.Server | None = None
        self._result: asyncio.Future[dict[str, str]] | None = None
        self._active = 0  # open connections; extras are dropped (local DoS bound)

    @property
    def redirect_uri(self) -> str:
        return f"http://{LOOPBACK}:{self.port}{CALLBACK_PATH}"

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("not started")
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self) -> None:
        self._result = asyncio.get_running_loop().create_future()
        try:
            self._server = await asyncio.start_server(
                self._handle, LOOPBACK, self._port, limit=MAX_REQUEST_HEAD
            )
        except OSError as e:
            raise LoginError(f"cannot listen on {LOOPBACK}:{self._port}: {e.strerror}") from e

    async def wait(self, timeout: float) -> dict[str, str]:
        if self._result is None:
            raise RuntimeError("not started")
        try:
            return await asyncio.wait_for(asyncio.shield(self._result), timeout)
        except TimeoutError:
            raise LoginError(f"no authorization response within {timeout:g}s") from None

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()

    async def _respond(self, writer: asyncio.StreamWriter, status: str, message: str) -> None:
        body = _PAGE.format(message).encode()
        head = f"HTTP/1.1 {status}\r\n{_SECURITY_HEADERS}Content-Length: {len(body)}\r\n\r\n"
        writer.write(head.encode() + body)
        with contextlib.suppress(ConnectionError):
            await writer.drain()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._active >= MAX_CALLBACK_CONNECTIONS:
            writer.close()
            return
        self._active += 1
        try:
            try:
                async with asyncio.timeout(HEAD_READ_TIMEOUT):
                    head = await reader.readuntil(b"\r\n\r\n")
            except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, OSError):
                return
            parts = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ")
            if len(parts) != 3 or parts[0] != "GET":
                await self._respond(writer, "405 Method Not Allowed", "Not supported.")
                return
            target = urlsplit(parts[1])
            done = self._result is None or self._result.done()
            if target.path != CALLBACK_PATH or done:
                await self._respond(writer, "404 Not Found", "Not found.")
                return
            raw = parse_qs(target.query, keep_blank_values=True)
            if any(len(v) != 1 for v in raw.values()):  # RFC 6749 §3.1: no repeated parameters
                await self._respond(writer, "400 Bad Request", "Login failed, see the terminal.")
                return
            params = {k: v[0] for k, v in raw.items()}
            # Bytes: compare_digest raises on non-ASCII str, and the state is attacker-supplied.
            if not hmac.compare_digest(params.get("state", "").encode(), self._state.encode()):
                await self._respond(writer, "400 Bad Request", "Login failed, see the terminal.")
                return
            ok = "code" in params and "error" not in params
            await self._respond(
                writer,
                "200 OK",
                "Login complete, you can close this tab."
                if ok
                else "Login failed, see the terminal.",
            )
            if self._result is not None and not self._result.done():
                self._result.set_result(params)
        except OSError:  # the browser (or anyone) hung up mid-response
            return
        finally:
            self._active -= 1
            writer.close()


# --- flow ---------------------------------------------------------------------------------


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _loopback_port(uris: tuple[str, ...]) -> int | None:
    """Port of the document's loopback redirect URI (0: any port), or None if absent."""
    for uri in uris:
        p = urlsplit(uri)
        if p.scheme == "http" and p.hostname == LOOPBACK and p.path == CALLBACK_PATH:
            return p.port or 0
    return None


async def _check_cimd(fetcher: Fetcher, url: str, wanted_port: int) -> int:
    """Validate the operator's client metadata document; return the listener port to use."""
    ex = await fetcher.request(
        "GET",
        url,
        headers={"Accept": "application/json"},
        follow_redirects=False,
        max_bytes=CIMD_FETCH_LIMIT,
    )
    if not ex.ok:
        raise LoginError(f"cannot fetch the client metadata document: {ex.error or ex.status}")
    doc, error = parse_document(ex.body)
    blocking = [
        f
        for f in lint(
            LintInput(
                source=url,
                document=doc,
                client_id_url=url,
                exchange=ex,
                raw_size=len(ex.body),
                parse_error=error,
            )
        )
        if f.severity.at_least(Severity.HIGH)
    ]
    if blocking:
        problems = "; ".join(f"{f.check_id}: {f.message}" for f in blocking[:3])
        raise LoginError(f"the client metadata document has blocking problems: {problems}")
    port = _loopback_port(_str_list((doc or {}).get("redirect_uris")))
    if port is None:
        raise LoginError(
            f"the client metadata document must list http://{LOOPBACK}{CALLBACK_PATH} "
            "(any port) or a fixed loopback port in redirect_uris"
        )
    if port and wanted_port and port != wanted_port:
        raise LoginError(f"the document registers port {port}, not --port {wanted_port}")
    return port or wanted_port


def _json_or_error(ex: HttpExchange, what: str) -> dict[str, Any]:
    doc = ex.json()
    if ex.status is None:
        raise LoginError(f"{what} failed: {ex.error}", unreachable=True)
    if not ex.ok or not isinstance(doc, dict):
        detail = ""
        if isinstance(doc, dict) and doc.get("error"):
            detail = f": {_text(doc.get('error'), 80)} {_text(doc.get('error_description', ''))}"
        raise LoginError(f"{what} failed (HTTP {ex.status}){detail}")
    return doc


@dataclass
class _Client:
    client_id: str
    strategy: Strategy
    secret: str | None = field(default=None, repr=False)
    auth_method: str | None = None
    management_uri: str | None = None
    management_token: str | None = field(default=None, repr=False)


async def _register(
    fetcher: Fetcher, server: _Server, endpoint: str, redirect_uri: str, redactor: Redactor
) -> _Client:
    # Some servers insist on refresh_token too (it is what MCP clients register); asking for
    # it changes nothing here: login discards refresh tokens.
    grants = ["authorization_code"]
    if "refresh_token" in server.grant_types:
        grants.append("refresh_token")
    ex = await fetcher.request(
        "POST",
        endpoint,
        json_body={
            "client_name": f"mcp-posture {__version__}",
            "redirect_uris": [redirect_uri],
            "grant_types": grants,
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
        headers={"Accept": "application/json"},
        follow_redirects=False,
    )
    doc = _json_or_error(ex, "client registration")
    client_id = doc.get("client_id")
    if not isinstance(client_id, str) or not client_id:
        raise LoginError("client registration returned no client_id")
    secret = doc.get("client_secret") if isinstance(doc.get("client_secret"), str) else None
    token = doc.get("registration_access_token")
    token = token if isinstance(token, str) else None
    for value in (secret, token):
        if value:
            redactor.add(value)
    uri = doc.get("registration_client_uri")
    method = doc.get("token_endpoint_auth_method")
    return _Client(
        client_id=client_id,
        strategy="dcr",
        secret=secret,
        auth_method=method if isinstance(method, str) else None,
        management_uri=uri if isinstance(uri, str) else None,
        management_token=token,
    )


def _reuse_hint(client: _Client, port: int) -> str:
    # The registered redirect URI carries this port, so a reuse must listen on it again.
    return f"--client-id {client.client_id} --port {port}"


async def _unregister(
    fetcher: Fetcher, server: _Server, client: _Client, ui: LoginUI, port: int
) -> None:
    uri, token = client.management_uri, client.management_token
    if (
        uri is None
        or token is None
        or server.registration_endpoint is None
        or not same_origin(uri, server.registration_endpoint)  # the token never leaves the AS
    ):
        ui.say(
            f"The registered client {client.client_id} stays on the authorization server "
            "(no usable RFC 7592 management endpoint). Reuse it next time instead of "
            f"registering another: {_reuse_hint(client, port)}; or remove it there."
        )
        return
    ex = await fetcher.request(
        "DELETE", uri, headers={"Authorization": f"Bearer {token}"}, follow_redirects=False
    )
    if ex.status in (200, 204):
        ui.say(f"Deleted the temporary client {client.client_id}.")
    else:
        ui.say(
            f"Could not delete the registered client {client.client_id} "
            f"(HTTP {ex.status}); remove it on the authorization server."
        )


def _jwt_audience(token: str) -> list[str] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, RecursionError):
        return None
    if not isinstance(claims, dict) or "aud" not in claims:
        return None
    aud = claims["aud"]
    if isinstance(aud, str):
        return [aud]
    return [a for a in aud if isinstance(a, str)] if isinstance(aud, list) else []


async def _choose_client(
    fetcher: Fetcher, server: _Server, opts: LoginOptions, ui: LoginUI
) -> tuple[Strategy, int, str | None]:
    """Pick the client identity in MCP's order: pre-registered, CIMD, DCR.

    Returns the strategy, the listener port it requires, and the CIMD URL if any.
    """
    if opts.client_id:
        return "pre-registered", opts.port, None
    if opts.client_metadata_url:
        if not server.cimd:
            raise LoginError(
                "the authorization server does not advertise Client ID Metadata Documents"
            )
        port = await _check_cimd(fetcher, opts.client_metadata_url, opts.port)
        return "cimd", port, opts.client_metadata_url
    explicit_dcr = opts.register is True and server.registration_endpoint is not None
    if server.cimd and opts.default_client and not explicit_dcr:
        try:
            port = await _check_cimd(fetcher, DEFAULT_CLIENT_METADATA_URL, opts.port)
        except LoginError as e:
            if server.registration_endpoint is None:
                raise
            ui.say(f"mcp-posture's client metadata document is unavailable ({e}).")
        else:
            return "cimd", port, DEFAULT_CLIENT_METADATA_URL
    if server.registration_endpoint is None:
        raise LoginError(
            "no way to obtain a client_id: pass --client-id"
            + (" or --client-metadata-url" if server.cimd else "")
        )
    allowed = opts.register
    if allowed is None and ui.confirm is not None:
        host = urlsplit(server.registration_endpoint).hostname
        allowed = ui.confirm(f"Register a new client on {host}?")
    if not allowed:
        raise LoginError(
            "Dynamic Client Registration creates a client on the authorization server: pass "
            "--register to allow it, or use --client-id / --client-metadata-url"
        )
    return "dcr", opts.port, None


async def _exchange(
    fetcher: Fetcher,
    server: _Server,
    client: _Client,
    code: str,
    verifier: str,
    redirect_uri: str,
    redactor: Redactor,
) -> dict[str, Any]:
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client.client_id,
        "code_verifier": verifier,
        "resource": server.resource,
    }
    headers = {"Accept": "application/json"}
    if client.secret:
        method = client.auth_method or (
            "client_secret_basic"
            if "client_secret_basic" in server.auth_methods or not server.auth_methods
            else "client_secret_post"
        )
        if method == "client_secret_post":
            form["client_secret"] = client.secret
        else:  # RFC 6749 §2.3.1: form-urlencode both parts before base64
            raw = f"{quote(client.client_id, safe='')}:{quote(client.secret, safe='')}"
            headers["Authorization"] = "Basic " + base64.b64encode(raw.encode()).decode()
            redactor.add(headers["Authorization"][6:])
    ex = await fetcher.request(
        "POST", server.token_endpoint, form=form, headers=headers, follow_redirects=False
    )
    doc = _json_or_error(ex, "token request")
    for key in ("access_token", "refresh_token", "id_token"):
        if isinstance(doc.get(key), str):
            redactor.add(doc[key])
    return doc


async def login(
    url: str,
    opts: LoginOptions,
    net: NetSettings,
    ui: LoginUI,
    *,
    redactor: Redactor,
    transport_factory: Callable[[], httpx.AsyncBaseTransport] | None = None,
) -> LoginResult:
    """Run the authorization code flow against ``url``; see the module docstring."""
    if opts.client_secret:
        redactor.add(opts.client_secret)
    transport = transport_factory() if transport_factory else None
    async with Fetcher(net, transport=transport) as fetcher:
        server = await _discover(fetcher, url, opts, net)
        warnings: list[str] = []
        if server.s256 is None:
            warnings.append(
                "PKCE S256 support is not advertised (2025-03-26 default endpoints); using it"
            )
        strategy, port, cimd_url = await _choose_client(fetcher, server, opts, ui)
        state = secrets.token_urlsafe(16)
        listener = CallbackServer(state, port)
        await listener.start()
        port_used = listener.port
        client: _Client | None = None
        try:
            redirect_uri = listener.redirect_uri
            if strategy == "pre-registered" and opts.client_id:
                client = _Client(opts.client_id, strategy, secret=opts.client_secret)
            elif strategy == "cimd" and cimd_url:
                client = _Client(cimd_url, strategy)
            elif server.registration_endpoint is not None:
                client = await _register(
                    fetcher, server, server.registration_endpoint, redirect_uri, redactor
                )
            else:  # pragma: no cover - _choose_client guarantees one of the above
                raise LoginError("no client identity")
            verifier, challenge = _pkce()
            redactor.add(verifier)
            query = {
                "response_type": "code",
                "client_id": client.client_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": server.resource,
            }
            if server.scope:
                query["scope"] = server.scope
            endpoint = server.authorization_endpoint
            authorize_url = f"{endpoint}{'&' if urlsplit(endpoint).query else '?'}" + urlencode(
                query
            )
            host = urlsplit(server.issuer).hostname
            ui.say(
                f"Log in to {host} (client: {strategy}"
                + (f", scope: {server.scope}" if server.scope else "")
                + ")."
            )
            opened: object = False
            if opts.open_browser:
                opened = ui.open_url(authorize_url)
                if inspect.isawaitable(opened):
                    task = asyncio.ensure_future(_await(opened))
                    opened = True
                    _keep(task)
            # Always show the URL: the browser may open in the wrong profile or window.
            ui.say(
                (
                    "Opened your browser. If it is the wrong profile or nothing happened, "
                    "open this URL yourself:"
                    if opened
                    else "Open this URL in your browser:"
                )
                + f"\n{authorize_url}"
            )
            ui.say(
                f"Waiting for the authorization response on {redirect_uri} ({opts.timeout:g}s)..."
            )
            params = await listener.wait(opts.timeout)
            await listener.close()
            if "error" in params:
                raise LoginError(
                    f"authorization failed: {_text(params['error'], 60)}"
                    + (
                        f": {_text(params['error_description'])}"
                        if params.get("error_description")
                        else ""
                    )
                )
            iss = params.get("iss")
            if (server.iss_supported and iss is None) or (iss is not None and iss != server.issuer):
                raise LoginError(
                    f"authorization response iss {_text(iss)!r} does not identify "
                    f"{server.issuer!r} (RFC 9207 mix-up defence)"
                )
            code = params.get("code")
            if not code:
                raise LoginError("authorization response has no code")
            redactor.add(code)
            doc = await _exchange(fetcher, server, client, code, verifier, redirect_uri, redactor)
            token = doc.get("access_token")
            if not isinstance(token, str) or not token:
                raise LoginError("token response has no access_token")
            token_type = str(doc.get("token_type", ""))
            if token_type.lower() != "bearer":
                raise LoginError(f"unsupported token_type {_text(token_type, 40)!r} (Bearer only)")
            granted = doc.get("scope") if isinstance(doc.get("scope"), str) else None
            if server.scope and granted is not None:
                missing = _scopes(server.scope) - _scopes(granted)
                if missing:
                    warnings.append(
                        f"scope granted is narrower; missing: {' '.join(sorted(missing))}"
                    )
            aud = _jwt_audience(token)
            if aud is not None and server.resource not in aud:
                warnings.append(
                    f"the token's aud ({', '.join(aud)}) does not include {server.resource}: "
                    "RFC 8707 audience binding is in doubt"
                )
            expires = doc.get("expires_in")
            return LoginResult(
                access_token=token,
                token_type="Bearer",  # noqa: S106 - the scheme name, not a secret
                scope=granted or server.scope,
                expires_in=expires if isinstance(expires, int) else None,
                client_id=client.client_id,
                strategy=strategy,
                issuer=server.issuer,
                resource=server.resource,
                warnings=tuple(warnings),
            )
        finally:
            await listener.close()
            if client is not None and client.strategy == "dcr":
                if opts.keep_client:
                    hint = _reuse_hint(client, port_used)
                    ui.say(f"Kept the registered client: reuse it with {hint}")
                else:
                    await _unregister(fetcher, server, client, ui, port_used)


_BACKGROUND: set[asyncio.Future[Any]] = set()


async def _await(value: Awaitable[Any]) -> Any:
    return await value


def _keep(task: asyncio.Future[Any]) -> None:
    _BACKGROUND.add(task)
    task.add_done_callback(_BACKGROUND.discard)
