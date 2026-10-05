"""TRN: transport hardening."""

from __future__ import annotations

import math
import ssl
import time
from collections.abc import Iterator
from urllib.parse import parse_qsl, urljoin, urlsplit

from mcp_posture.checks import _refs as R
from mcp_posture.context import ScanContext, exchange_evidence
from mcp_posture.models import (
    Confidence,
    Evidence,
    Finding,
    Severity,
    SpecRevision,
    revisions_from,
    revisions_until,
)
from mcp_posture.net import is_loopback_host
from mcp_posture.registry import check

EXPIRY_WARNING_DAYS = 30
MIN_SESSION_ID_BITS = 64


@check(
    id="MCPP-TRN01",
    title="MCP endpoint not served over HTTPS",
    severity=Severity.CRITICAL,
    references=[R.MCP_AUTH_2025_11, R.RFC9325, R.OAUTH21],
    rationale="""Bearer tokens, tool arguments and results travel in clear text over plain
        HTTP. The MCP authorization spec requires HTTPS for all authorization-related traffic,
        and bearer tokens must only be sent over TLS.""",
    remediation="""Serve the MCP endpoint over HTTPS only (TLS 1.2+), and redirect or refuse
        plain HTTP. Loopback development servers are exempt.""",
)
def trn01(ctx: ScanContext) -> Iterator[Finding]:
    for url in filter(None, (ctx.url, ctx.mcp.legacy_endpoint)):
        full = urljoin(ctx.url, url)
        p = urlsplit(full)
        if p.scheme == "http" and not is_loopback_host(p.hostname or ""):
            yield ctx.finding(
                "MCPP-TRN01",
                f"{full} uses plain HTTP.",
                location=full,
                evidence=[Evidence(summary="URL scheme is http", request=full)],
            )


@check(
    id="MCPP-TRN02",
    title="Legacy TLS (1.0/1.1) accepted",
    severity=Severity.HIGH,
    references=[R.RFC8996, R.RFC9325, R.RFC8414],
    rationale="""TLS 1.0 and 1.1 are deprecated (RFC 8996) and have known weaknesses.
        RFC 8414 requires TLS 1.2 for authorization servers; BCP 195 applies to protected
        resources (RFC 9728 §7.1).""",
    remediation="""Set the minimum TLS version to 1.2 (prefer 1.3) on the load balancer,
        reverse proxy or gateway in front of the server.""",
)
def trn02(ctx: ScanContext) -> Iterator[Finding]:
    for t in ctx.tls:
        if t.legacy_accepted:
            yield ctx.finding(
                "MCPP-TRN02",
                f"{t.host}:{t.port} completed a handshake offering only TLS 1.0/1.1 "
                f"(negotiated {t.legacy_version}).",
                location=f"https://{t.host}:{t.port}",
                evidence=[Evidence(summary=f"negotiated {t.legacy_version}")],
            )


@check(
    id="MCPP-TRN03",
    title="TLS certificate invalid or expiring",
    severity=Severity.HIGH,
    references=[R.RFC9325, R.RFC9728],
    rationale="""Clients must validate the server certificate (RFC 9728 §7.3, RFC 8414 §6).
        An invalid certificate forces clients to disable validation or fail; an expiring one
        is an outage waiting to happen.""",
    remediation="""Serve a certificate from a publicly trusted CA that matches the hostname,
        and automate renewal (ACME).""",
)
def trn03(ctx: ScanContext) -> Iterator[Finding]:
    now = time.time()
    for t in ctx.tls:
        loc = f"https://{t.host}:{t.port}"
        if not t.verified and t.error and "certificate" in t.error:
            yield ctx.finding(
                "MCPP-TRN03",
                f"{t.host}:{t.port}: {t.error}.",
                location=loc,
                evidence=[Evidence(summary=t.error)],
            )
        elif t.verified and t.not_after:
            try:
                expires = ssl.cert_time_to_seconds(t.not_after)
            except ValueError:
                continue
            days = (expires - now) / 86400
            if days < EXPIRY_WARNING_DAYS:
                yield ctx.finding(
                    "MCPP-TRN03",
                    f"Certificate for {t.host} expires in {max(days, 0):.0f} days.",
                    location=loc,
                    severity=Severity.LOW,
                    key="expiring",
                    evidence=[Evidence(summary=f"notAfter {t.not_after}")],
                )


@check(
    id="MCPP-TRN04",
    title="Plain HTTP not redirected to HTTPS",
    severity=Severity.MEDIUM,
    references=[R.RFC6797, R.MCP_AUTH_2025_11],
    rationale="""When the plain-HTTP port answers with content instead of a redirect,
        misconfigured clients can send tokens in clear text without noticing.""",
    remediation="""Answer every plain HTTP request with a 301/308 redirect to the HTTPS URL
        (and never process the request), or close port 80 entirely.""",
)
def trn04(ctx: ScanContext) -> Iterator[Finding]:
    for ex in ctx.plain_http:
        if ex.status is None:
            continue  # nothing listening on port 80: fine
        location = ex.header("location") or ""
        if ex.status in (301, 302, 307, 308) and urlsplit(location).scheme == "https":
            continue
        yield ctx.finding(
            "MCPP-TRN04",
            f"{ex.url} answered HTTP {ex.status} instead of redirecting to HTTPS.",
            location=ex.url,
            evidence=[exchange_evidence(ex, "plain HTTP response")],
        )


@check(
    id="MCPP-TRN05",
    title="HSTS header missing",
    severity=Severity.LOW,
    references=[R.RFC6797],
    rationale="""Without Strict-Transport-Security, a network attacker can downgrade the
        first connection of browser-based clients to plain HTTP.""",
    remediation="""Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`
        on every HTTPS response.""",
)
def trn05(ctx: ScanContext) -> Iterator[Finding]:
    if urlsplit(ctx.url).scheme != "https":
        return
    origin = ctx.target.origin
    responses = [
        ex for ex in ctx.exchanges if ex.status is not None and ex.url.startswith(origin + "/")
    ]
    if not responses:
        return
    values = [ex.header("strict-transport-security") for ex in responses]
    if not any(values):
        yield ctx.finding(
            "MCPP-TRN05",
            f"No Strict-Transport-Security header on {len(responses)} HTTPS response(s).",
            location=origin,
            evidence=[exchange_evidence(responses[0], "response without HSTS", 0)],
        )


@check(
    id="MCPP-TRN06",
    title="Legacy HTTP+SSE transport only",
    severity=Severity.MEDIUM,
    references=[R.MCP_TRANSPORT_2025_11, R.MCP_TRANSPORT_2026],
    rationale="""The HTTP+SSE transport (2024-11-05) is replaced by Streamable HTTP since
        2025-03-26 and formally deprecated in 2026-07-28. It carries the session identifier
        in the URL and lacks the protocol-version and Origin requirements of the new
        transport.""",
    remediation="""Expose a Streamable HTTP endpoint (single POST endpoint). Keep the SSE
        endpoint only for legacy clients, behind the same authorization.""",
)
def trn06(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.mcp.transport == "legacy-sse":
        sev = Severity.LOW if ctx.revision == SpecRevision.R2025_03_26 else Severity.MEDIUM
        yield ctx.finding(
            "MCPP-TRN06",
            "The endpoint only speaks the legacy HTTP+SSE transport.",
            severity=sev,
            evidence=[Evidence(summary=f"endpoint event: {ctx.mcp.legacy_endpoint}")],
        )


_SESSION_PARAM_HINTS = ("session", "sid")


@check(
    id="MCPP-TRN07",
    title="Session identifier carried in a URL",
    severity=Severity.HIGH,
    references=[R.MCP_TRANSPORT_2025_11, R.MCP_SECURITY_BP],
    rationale="""URLs end up in access logs, proxies, browser history and Referer headers.
        A session identifier in a URL can be replayed by anyone who reads those logs
        (session hijacking).""",
    remediation="""Carry the session only in the `Mcp-Session-Id` header (Streamable HTTP),
        never in a query string or path.""",
)
def trn07(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.mcp.legacy_endpoint:
        query = dict(parse_qsl(urlsplit(ctx.mcp.legacy_endpoint).query))
        keys = [k for k in query if any(h in k.lower() for h in _SESSION_PARAM_HINTS)]
        if keys:
            yield ctx.finding(
                "MCPP-TRN07",
                f"The SSE endpoint URL carries the session in query parameter(s) {keys}.",
                severity=Severity.MEDIUM,
                location=urljoin(ctx.url, ctx.mcp.legacy_endpoint),
                evidence=[Evidence(summary="legacy SSE endpoint event", excerpt=", ".join(keys))],
            )
    for sid in ctx.mcp.session_ids:
        for ex in ctx.exchanges:
            for _, location in ex.redirects:
                if sid in location:
                    yield ctx.finding(
                        "MCPP-TRN07",
                        "A redirect Location contains the session identifier.",
                        key="redirect",
                        location=ex.url,
                        evidence=[exchange_evidence(ex, "redirect with session id", 0)],
                    )


def _estimated_bits(sid: str) -> float:
    if all(c in "0123456789" for c in sid):
        alphabet = 10
    elif all(c in "0123456789abcdefABCDEF-" for c in sid):
        alphabet = 16
    elif all(c.isalnum() for c in sid):
        alphabet = 62
    else:
        alphabet = 64
    payload = len(sid.replace("-", "")) if alphabet == 16 else len(sid)
    return payload * math.log2(alphabet)


def _as_int(sid: str) -> int | None:
    for base in (10, 16):
        try:
            return int(sid.replace("-", ""), base)
        except ValueError:
            continue
    return None


@check(
    id="MCPP-TRN08",
    title="Weak Mcp-Session-Id",
    severity=Severity.HIGH,
    revisions=revisions_until(SpecRevision.R2025_11_25),
    references=[R.MCP_TRANSPORT_2025_11, R.MCP_SECURITY_BP],
    rationale="""Session IDs SHOULD be globally unique and cryptographically secure and MUST
        contain only visible ASCII. Guessable identifiers let an attacker inject events into
        or hijack another user's session.""",
    remediation="""Generate session IDs from a CSPRNG with at least 128 bits of entropy
        (e.g. `secrets.token_urlsafe(32)` or a random UUIDv4), bind them to the
        authenticated user, and never reuse them.""",
)
def trn08(ctx: ScanContext) -> Iterator[Finding]:
    sids = ctx.mcp.session_ids
    if not sids:
        return
    bad = sum(1 for sid in sids for c in sid if not 0x21 <= ord(c) <= 0x7E)
    if bad:
        yield ctx.finding(
            "MCPP-TRN08",
            "Session ID contains characters outside visible ASCII (0x21-0x7E).",
            severity=Severity.MEDIUM,
            key="charset",
            evidence=[Evidence(summary=f"{bad} invalid character(s)")],
        )
    weakest = min(sids, key=_estimated_bits)
    bits = _estimated_bits(weakest)
    if bits < MIN_SESSION_ID_BITS:
        yield ctx.finding(
            "MCPP-TRN08",
            f"Session ID is short ({len(weakest)} chars, about {bits:.0f} bits at best).",
            key="short",
            evidence=[Evidence(summary=f"length {len(weakest)}")],
        )
    if len(sids) >= 2:
        a, b = sids[0], sids[1]
        ia, ib = _as_int(a), _as_int(b)
        if a == b:
            yield ctx.finding(
                "MCPP-TRN08",
                "Two independent initialize requests received the same session ID.",
                key="identical",
                evidence=[Evidence(summary="identical session IDs across sessions")],
            )
        elif ia is not None and ib is not None and abs(ia - ib) < 1_000_000:
            yield ctx.finding(
                "MCPP-TRN08",
                "Session IDs look sequential (numerically close across two sessions).",
                key="sequential",
                confidence=Confidence.MEDIUM,
                evidence=[Evidence(summary=f"difference {abs(ia - ib)}")],
            )


@check(
    id="MCPP-TRN09",
    title="Session ID minted on a stateless revision",
    severity=Severity.INFO,
    revisions=revisions_from(SpecRevision.R2026_07_28),
    references=[R.MCP_TRANSPORT_2026],
    rationale="""Revision 2026-07-28 removed protocol sessions: servers should not mint or
        echo `Mcp-Session-Id`. A leftover session layer is unused attack surface.""",
    remediation="""Drop session handling when serving 2026-07-28 clients; keep per-request
        authorization.""",
)
def trn09(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.mcp.era == "modern" and ctx.mcp.session_ids:
        yield ctx.finding(
            "MCPP-TRN09",
            "The server returned an Mcp-Session-Id header on a 2026-07-28 request.",
        )


@check(
    id="MCPP-TRN10",
    title="Weak security headers on discovery endpoints",
    severity=Severity.LOW,
    references=[R.RFC9700, R.RFC9728],
    rationale="""Metadata documents steer clients to authorization servers. They should not
        be MIME-sniffable, and must never be readable cross-origin with credentials.""",
    remediation="""Serve metadata as `application/json` with `X-Content-Type-Options: nosniff`.
        Public CORS (`*`) is fine for metadata, but never combine it with
        `Access-Control-Allow-Credentials: true`.""",
)
def trn10(ctx: ScanContext) -> Iterator[Finding]:
    docs = [f for f in ctx.auth.prm_fetches if f.found]
    for s in ctx.auth.authorization_servers:
        docs.extend(f for f in s.fetches if f.found)
    seen: set[str] = set()
    for f in docs:
        ex = f.exchange
        # Headers are those of the final response: a redirecting variant (e.g. the root PRM
        # redirecting to the path-inserted one) is the same document, reported once.
        url = ex.final_url or f.url
        if url in seen:
            continue
        seen.add(url)
        problems = []
        if (ex.header("x-content-type-options") or "").lower() != "nosniff":
            problems.append("missing X-Content-Type-Options: nosniff")
        acao = ex.header("access-control-allow-origin")
        creds = (ex.header("access-control-allow-credentials") or "").lower() == "true"
        severity = Severity.LOW
        if acao and creds and acao in ("*", "null"):
            problems.append(f"Access-Control-Allow-Origin {acao} with credentials")
            severity = Severity.MEDIUM
        if problems:
            yield ctx.finding(
                "MCPP-TRN10",
                f"{url}: {'; '.join(problems)}.",
                location=url,
                severity=severity,
                evidence=[exchange_evidence(ex, "metadata response headers", 0)],
            )


@check(
    id="MCPP-TRN11",
    title="MCP endpoint redirects",
    severity=Severity.INFO,
    references=[R.MCP_TRANSPORT_2026, R.RFC9728],
    rationale="""The URL users configure is the resource identifier: clients compare it with
        PRM `resource` and send it as the RFC 8707 `resource` parameter. When the endpoint
        redirects (often a framework adding a trailing slash), some clients do not follow
        redirects on POST, and a redirect to another origin drops the bearer token. The scanner
        follows same-origin 307/308 redirects like a client would, and never follows across
        origins.""",
    remediation="""Serve the MCP endpoint at the URL you publish without a redirect (or
        publish the final URL), and keep PRM `resource` equal to that URL.""",
)
def trn11(ctx: ScanContext) -> Iterator[Finding]:
    hops = ctx.mcp.endpoint_redirects
    if not hops:
        return
    final = hops[-1][1]
    chain = " -> ".join(f"{status} {url}" for status, url in hops)
    cross = (
        urlsplit(final)[:2] != urlsplit(ctx.url)[:2]
        or urlsplit(final).port != urlsplit(ctx.url).port
    )
    if cross:
        message = (
            f"The endpoint redirects to another origin ({chain}); not followed, so the scan "
            "stopped there. Scan the final URL directly if it is yours."
        )
    else:
        message = f"The endpoint redirects ({chain}); the scan followed it."
    yield ctx.finding(
        "MCPP-TRN11",
        message,
        severity=Severity.LOW if cross else Severity.INFO,
        evidence=[Evidence(summary="endpoint redirects", excerpt=chain)],
    )
