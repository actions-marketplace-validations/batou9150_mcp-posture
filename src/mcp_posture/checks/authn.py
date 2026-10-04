"""AUTHN: authentication challenge and unauthenticated exposure."""

from __future__ import annotations

import re
from collections.abc import Iterator

from mcp_posture.checks import _refs as R
from mcp_posture.checks._util import is_https, same_origin
from mcp_posture.context import ScanContext, exchange_evidence
from mcp_posture.discovery import bearer_challenge
from mcp_posture.models import (
    Confidence,
    Evidence,
    Finding,
    Severity,
    SpecRevision,
    revisions_from,
)
from mcp_posture.net import HttpExchange
from mcp_posture.registry import check

_DESTRUCTIVE = re.compile(r"^(delete|drop|remove|destroy|purge|truncate|wipe|kill|exec|run)", re.I)


@check(
    id="MCPP-AUTHN01",
    title="MCP tools listed without authentication",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    references=[R.MCP_AUTH_2025_11, R.MCP_SECURITY_BP],
    rationale="""Anyone who can reach the endpoint can enumerate (and likely call) the server's
        tools. Some servers are public on purpose, hence medium confidence; for anything that
        touches user or company data this is an authentication bypass.""",
    remediation="""Require an OAuth access token on every MCP request (return 401 with a
        `WWW-Authenticate: Bearer resource_metadata=...` challenge), or document the server
        as intentionally public and suppress this finding with a justification.""",
)
def authn01(ctx: ScanContext) -> Iterator[Finding]:
    if not ctx.mcp.surface_listed_unauthenticated:
        return
    tools = [i for i in ctx.mcp.surface if i.kind == "tool"]
    risky = [t.name for t in tools if _DESTRUCTIVE.match(t.name)]
    advertises_auth = ctx.auth.prm is not None
    severity = Severity.MEDIUM if advertises_auth and not risky else Severity.HIGH
    detail = f" including {', '.join(risky[:5])}" if risky else ""
    yield ctx.finding(
        "MCPP-AUTHN01",
        f"tools/list answered without credentials ({len(tools)} tool(s){detail}).",
        severity=severity,
        evidence=[Evidence(summary=f"{len(ctx.mcp.surface)} item(s) listed anonymously")],
    )


@check(
    id="MCPP-AUTHN02",
    title="401 without a Bearer challenge",
    severity=Severity.MEDIUM,
    references=[R.RFC6750, R.MCP_AUTH_2025_06, R.RFC9728_5_1],
    rationale="""RFC 6750 §3 requires a `WWW-Authenticate: Bearer` header on 401 responses.
        Without it, MCP clients cannot discover where to obtain a token and the
        authorization flow never starts.""",
    remediation="""Return `WWW-Authenticate: Bearer resource_metadata="<PRM URL>",
        scope="<scopes>"` on every 401.""",
)
def authn02(ctx: ScanContext) -> Iterator[Finding]:
    ex = ctx.mcp.unauth_exchange
    if not ctx.mcp.auth_required or ex is None:
        return
    if bearer_challenge(ctx.mcp.challenges) is not None:
        return
    severity = {
        SpecRevision.R2025_03_26: Severity.LOW,
        SpecRevision.R2025_06_18: Severity.HIGH,
    }.get(ctx.revision, Severity.MEDIUM)
    schemes = ", ".join(c.scheme for c in ctx.mcp.challenges) or "none"
    yield ctx.finding(
        "MCPP-AUTHN02",
        f"The 401 response carries no Bearer challenge (schemes seen: {schemes}).",
        severity=severity,
        evidence=[exchange_evidence(ex, "unauthenticated MCP request", 0)],
    )


@check(
    id="MCPP-AUTHN03",
    title="No way to discover Protected Resource Metadata",
    severity=Severity.HIGH,
    revisions=revisions_from(SpecRevision.R2025_06_18),
    references=[R.RFC9728_5_1, R.MCP_AUTH_2025_11, R.MCP_AUTH_DISCOVERY_2026],
    rationale="""MCP servers MUST advertise their PRM, through `resource_metadata` in the
        401 challenge (mandatory in 2025-06-18) or a well-known URL (allowed since
        2025-11-25). Without it, clients cannot find the authorization server.""",
    remediation="""Add `resource_metadata="https://<host>/.well-known/oauth-protected-resource<path>"`
        to the Bearer challenge and serve that document.""",
)
def authn03(ctx: ScanContext) -> Iterator[Finding]:
    if not ctx.mcp.auth_required:
        return
    bearer = bearer_challenge(ctx.mcp.challenges)
    if bearer is not None and bearer.get("resource_metadata"):
        return
    well_known = [f for f in ctx.auth.prm_fetches if f.found and f.variant != "www-authenticate"]
    if ctx.revision.at_least(SpecRevision.R2025_11_25) and well_known:
        return
    msg = "The 401 challenge has no resource_metadata parameter"
    if ctx.revision == SpecRevision.R2025_06_18:
        msg += " (mandatory in 2025-06-18)"
    else:
        msg += " and no PRM document was found at the well-known URLs"
    ex = ctx.mcp.unauth_exchange
    evidence = [exchange_evidence(ex, "challenge", 0)] if ex is not None else []
    yield ctx.finding("MCPP-AUTHN03", msg + ".", evidence=evidence)


@check(
    id="MCPP-AUTHN04",
    title="resource_metadata URL not HTTPS or on another origin",
    severity=Severity.MEDIUM,
    revisions=revisions_from(SpecRevision.R2025_06_18),
    references=[R.RFC9728_5_1, R.RFC9728],
    rationale="""The PRM URL tells clients which authorization server to trust. Over plain
        HTTP it can be tampered with; on another origin it deserves a look, since the
        server delegates trust to a third party.""",
    remediation="""Serve the PRM over HTTPS, preferably from the MCP server's own origin.""",
)
def authn04(ctx: ScanContext) -> Iterator[Finding]:
    bearer = bearer_challenge(ctx.mcp.challenges)
    url = bearer.get("resource_metadata") if bearer else None
    if not url:
        return
    if not is_https(url):
        yield ctx.finding(
            "MCPP-AUTHN04",
            f"resource_metadata points to a non-HTTPS URL: {url}.",
            location=url,
        )
    elif not same_origin(url, ctx.url):
        yield ctx.finding(
            "MCPP-AUTHN04",
            f"resource_metadata points to another origin: {url}.",
            location=url,
            severity=Severity.INFO,
        )


@check(
    id="MCPP-AUTHN05",
    title="Error code in an unauthenticated challenge",
    severity=Severity.LOW,
    references=[R.RFC6750_3_1],
    rationale="""RFC 6750 §3.1: when a request carries no authentication, the resource server
        SHOULD NOT include an error code. Doing so leaks validation details and confuses
        clients that treat `invalid_token` as a reason to drop credentials.""",
    remediation="""Return a bare `Bearer` challenge (realm, resource_metadata, scope) when no
        token was sent; reserve `error=` for requests that included a token.""",
)
def authn05(ctx: ScanContext) -> Iterator[Finding]:
    bearer = bearer_challenge(ctx.mcp.challenges)
    if bearer is not None and bearer.get("error") and ctx.mcp.unauth_exchange is not None:
        yield ctx.finding(
            "MCPP-AUTHN05",
            f"Unauthenticated 401 carries error={bearer.get('error')!r}.",
            evidence=[exchange_evidence(ctx.mcp.unauth_exchange, "challenge", 0)],
        )


_LEAKS: tuple[tuple[str, re.Pattern[str], Severity], ...] = (
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)"), Severity.MEDIUM),
    ("Java stack trace", re.compile(r"\n\s+at [\w$.]+\([\w$]+\.java:\d+\)"), Severity.MEDIUM),
    ("Node.js stack trace", re.compile(r"\n\s+at .+ \(/[^)]+:\d+:\d+\)"), Severity.MEDIUM),
    (".NET stack trace", re.compile(r"\n\s+at [\w.<>`]+\(.*\) in .+:line \d+"), Severity.MEDIUM),
    ("Go panic", re.compile(r"goroutine \d+ \[running\]"), Severity.MEDIUM),
    (
        "debug page",
        re.compile(r"(Werkzeug Debugger|DEBUG = True|Whitelabel Error Page)"),
        Severity.MEDIUM,
    ),
    (
        "SQL error",
        re.compile(r"(SQLSTATE\[|syntax error at or near|ORA-\d{5}|psycopg2?\.)", re.I),
        Severity.MEDIUM,
    ),
    (
        "private IP address",
        re.compile(
            r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
            r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
        ),
        Severity.LOW,
    ),
    (
        "server filesystem path",
        re.compile(
            r"(/home/\w+/|/usr/src/app/|/var/www/|/opt/[\w-]+/.+\.(py|js|rb|java)|[A-Z]:\\\\)"
        ),
        Severity.LOW,
    ),
)
_VERSION_BANNER = re.compile(r"[A-Za-z][\w.-]*/\d+(\.\d+)+")


def _error_responses(ctx: ScanContext) -> list[HttpExchange]:
    out = [
        ex
        for ex in ctx.exchanges
        if ex.status is not None and ex.status >= 400 and ex.url.startswith(ctx.target.origin)
    ]
    return out


@check(
    id="MCPP-AUTHN06",
    title="Error responses leak internals",
    severity=Severity.MEDIUM,
    references=[R.OWASP_ERROR_HANDLING],
    rationale="""Stack traces, debug pages, internal addresses and version banners help an
        attacker fingerprint the stack and find known vulnerabilities.""",
    remediation="""Return generic error bodies (JSON-RPC error objects or RFC 6750 challenges)
        and log details server-side. Strip `Server` / `X-Powered-By` version banners at
        the proxy.""",
)
def authn06(ctx: ScanContext) -> Iterator[Finding]:
    seen: set[str] = set()
    for ex in _error_responses(ctx):
        text = ex.text
        for label, pattern, severity in _LEAKS:
            m = pattern.search(text)
            if m and label not in seen:
                seen.add(label)
                yield ctx.finding(
                    "MCPP-AUTHN06",
                    f"HTTP {ex.status} response body contains a {label}.",
                    location=ex.url,
                    severity=severity,
                    key=label,
                    evidence=[
                        Evidence(
                            summary=label,
                            request=ex.describe(),
                            status=ex.status,
                            excerpt=text[max(0, m.start() - 40) : m.end() + 80],
                        )
                    ],
                )
    banners = []
    for ex in ctx.exchanges:
        if not ex.url.startswith(ctx.target.origin):
            continue
        for name in ("server", "x-powered-by", "x-aspnet-version"):
            value = ex.header(name)
            if value and _VERSION_BANNER.search(value) and (name, value) not in banners:
                banners.append((name, value))
    if banners:
        yield ctx.finding(
            "MCPP-AUTHN06",
            "Response headers disclose software versions: "
            + ", ".join(f"{n}: {v}" for n, v in banners)
            + ".",
            location=ctx.target.origin,
            severity=Severity.LOW,
            key="banner",
        )
