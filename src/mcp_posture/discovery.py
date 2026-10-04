"""OAuth discovery: 401 challenges, Protected Resource Metadata, Authorization Server Metadata."""

from __future__ import annotations

import re
from collections.abc import Iterable
from types import MappingProxyType
from urllib.parse import urlsplit, urlunsplit

from mcp_posture.context import (
    AuthDiscovery,
    AuthServerInfo,
    Challenge,
    MetadataFetch,
    freeze,
)
from mcp_posture.net import Fetcher, HttpExchange

PRM_WELL_KNOWN = "/.well-known/oauth-protected-resource"
AS_WELL_KNOWN = "/.well-known/oauth-authorization-server"
OIDC_WELL_KNOWN = "/.well-known/openid-configuration"
MAX_AUTHORIZATION_SERVERS = 5

_TOKEN = r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"  # noqa: S105 - RFC 9110 token grammar
_TOKEN_RE = re.compile(_TOKEN)
_TOKEN68_RE = re.compile(r"[A-Za-z0-9\-._~+/]+=*")


def parse_www_authenticate(values: Iterable[str]) -> tuple[Challenge, ...]:
    """Parse one or more WWW-Authenticate header values (RFC 9110 §11.6.1).

    Tolerant: never raises; malformed input yields whatever could be parsed.
    """
    out: list[Challenge] = []
    for value in values:
        out.extend(_parse_one(value))
    return tuple(out)


def _parse_one(s: str) -> list[Challenge]:
    i, n = 0, len(s)
    challenges: list[Challenge] = []
    scheme: str | None = None
    params: dict[str, str] = {}
    token68: str | None = None

    def flush() -> None:
        nonlocal scheme, params, token68
        if scheme:
            challenges.append(Challenge(scheme, MappingProxyType(params), token68))
        scheme, params, token68 = None, {}, None

    def skip_ws_commas(j: int) -> int:
        while j < n and s[j] in " \t,":
            j += 1
        return j

    while True:
        i = skip_ws_commas(i)
        if i >= n:
            break
        m = _TOKEN_RE.match(s, i)
        if not m:
            i += 1  # skip garbage
            continue
        name, j = m.group(0), m.end()
        k = j
        while k < n and s[k] in " \t":
            k += 1
        if k < n and s[k] == "=" and scheme is not None and not _looks_like_token68_end(s, k):
            # auth-param
            k += 1
            while k < n and s[k] in " \t":
                k += 1
            value, i = _read_value(s, k)
            params.setdefault(name.lower(), value)
            continue
        # new challenge (scheme)
        flush()
        scheme = name
        i = j
        # token68?
        k = i
        while k < n and s[k] in " \t":
            k += 1
        m68 = _TOKEN68_RE.match(s, k)
        if m68 and k > i:
            after = m68.end()
            rest = s[after:].lstrip(" \t")
            if (not rest or rest.startswith(",")) and "=" not in s[k : m68.end()].rstrip("="):
                token68 = m68.group(0)
                i = after
    flush()
    return challenges


def _looks_like_token68_end(s: str, k: int) -> bool:
    """``abc==`` style token68 endings are not parameters."""
    j = k
    while j < len(s) and s[j] == "=":
        j += 1
    rest = s[j:].lstrip(" \t")
    return j - k > 1 or (j - k == 1 and (not rest or rest.startswith(",")))


def _read_value(s: str, i: int) -> tuple[str, int]:
    n = len(s)
    if i < n and s[i] == '"':
        out: list[str] = []
        i += 1
        while i < n:
            c = s[i]
            if c == "\\" and i + 1 < n:
                out.append(s[i + 1])
                i += 2
                continue
            if c == '"':
                return "".join(out), i + 1
            out.append(c)
            i += 1
        return "".join(out), i
    m = _TOKEN_RE.match(s, i)
    if m:
        return m.group(0), m.end()
    j = i
    while j < n and s[j] not in ", \t":
        j += 1
    return s[i:j], j


def bearer_challenge(challenges: Iterable[Challenge]) -> Challenge | None:
    return next((c for c in challenges if c.scheme.lower() == "bearer"), None)


def well_known_insert(url: str, suffix: str) -> str:
    """RFC 8414 / RFC 9728 path insertion: ``https://h/p`` → ``https://h/.well-known/x/p``."""
    p = urlsplit(url)
    path = p.path.rstrip("/")
    return urlunsplit((p.scheme, p.netloc, f"{suffix}{path}", p.query, ""))


def well_known_root(url: str, suffix: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, suffix, "", ""))


def well_known_append(url: str, suffix: str) -> str:
    """OIDC Discovery appends: ``https://h/p`` → ``https://h/p/.well-known/openid-configuration``."""
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, f"{p.path.rstrip('/')}{suffix}", "", ""))


def prm_candidates(server_url: str, challenge_url: str | None) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if challenge_url:
        out.append(("www-authenticate", challenge_url))
    out.append(("path-insertion", well_known_insert(server_url, PRM_WELL_KNOWN)))
    out.append(("root", well_known_root(server_url, PRM_WELL_KNOWN)))
    seen: set[str] = set()
    deduped = []
    for variant, url in out:
        if url not in seen:
            seen.add(url)
            deduped.append((variant, url))
    return deduped


def as_metadata_candidates(issuer: str) -> list[tuple[str, str]]:
    has_path = urlsplit(issuer).path.strip("/") != ""
    out = [
        ("rfc8414", well_known_insert(issuer, AS_WELL_KNOWN)),
        ("oidc-insert", well_known_insert(issuer, OIDC_WELL_KNOWN)),
    ]
    if has_path:
        out.append(("oidc-append", well_known_append(issuer, OIDC_WELL_KNOWN)))
    return out


def json_document(ex: HttpExchange) -> dict[str, object] | None:
    if not ex.ok:
        return None
    doc = ex.json()
    return doc if isinstance(doc, dict) else None


async def fetch_metadata(
    fetcher: Fetcher, variant: str, url: str, expected_id: str | None
) -> MetadataFetch:
    ex = await fetcher.request("GET", url, headers={"Accept": "application/json"})
    doc = json_document(ex)
    return MetadataFetch(
        variant=variant,
        url=url,
        exchange=ex,
        document=freeze(doc) if doc is not None else None,
        expected_id=expected_id,
    )


async def discover_auth(
    fetcher: Fetcher,
    server_url: str,
    challenge_url: str | None,
    *,
    legacy_origin_as: bool = False,
) -> AuthDiscovery:
    """Fetch every PRM variant (so inconsistencies are visible), then each listed AS."""
    prm_fetches = tuple(
        [
            await fetch_metadata(fetcher, variant, url, expected_id=server_url)
            for variant, url in prm_candidates(server_url, challenge_url)
        ]
    )
    prm = next((f for f in prm_fetches if f.found), None)
    issuers: list[str] = []
    if prm is not None and prm.document is not None:
        raw = prm.document.get("authorization_servers")
        if isinstance(raw, tuple):
            issuers = [i for i in raw if isinstance(i, str)][:MAX_AUTHORIZATION_SERVERS]
    servers = []
    for issuer in issuers:
        servers.append(await discover_as(fetcher, issuer))

    legacy_as = None
    fallbacks: tuple[HttpExchange, ...] = ()
    if legacy_origin_as and prm is None:
        # 2025-03-26: metadata at the origin of the MCP server, path discarded.
        origin = well_known_root(server_url, "")
        legacy_as = AuthServerInfo(
            issuer=origin,
            fetches=(
                await fetch_metadata(
                    fetcher, "legacy-origin", well_known_root(server_url, AS_WELL_KNOWN), origin
                ),
            ),
        )
        if legacy_as.document is None:
            fallbacks = tuple(
                [
                    await fetcher.request("GET", well_known_root(server_url, path))
                    for path in ("/authorize", "/token", "/register")
                ]
            )
    return AuthDiscovery(
        prm_fetches=prm_fetches,
        authorization_servers=tuple(servers),
        legacy_as=legacy_as,
        legacy_fallback_endpoints=fallbacks,
    )


async def discover_as(fetcher: Fetcher, issuer: str) -> AuthServerInfo:
    fetches: list[MetadataFetch] = []
    for variant, url in as_metadata_candidates(issuer):
        f = await fetch_metadata(fetcher, variant, url, expected_id=issuer)
        fetches.append(f)
        if f.found:
            break
    return AuthServerInfo(issuer=issuer, fetches=tuple(fetches))
