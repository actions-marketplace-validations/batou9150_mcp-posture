"""SCP: OAuth scopes advertised by the resource and its authorization servers."""

from __future__ import annotations

import re
from collections.abc import Iterator

from mcp_posture.checks import _refs as R
from mcp_posture.checks._util import auth_servers, str_list
from mcp_posture.context import ScanContext, exchange_evidence
from mcp_posture.discovery import bearer_challenge
from mcp_posture.models import Confidence, Evidence, Finding, Severity, SpecRevision, revisions_from
from mcp_posture.registry import check

_BROAD = re.compile(
    r"^(\*|all|admin|administrator|root|superuser|super_user|sudo|god|full|full_access|"
    r"full-access|fullaccess|everything|any)$|[:./_-]\*$|^\*[:./_-]|[:./](admin|all|full)$",
    re.I,
)


def is_broad(scope: str) -> bool:
    return _BROAD.search(scope) is not None


def _resource_scopes(ctx: ScanContext) -> list[tuple[str, str]]:
    """(source, scope) pairs advertised by the MCP server itself."""
    out: list[tuple[str, str]] = []
    prm = ctx.auth.prm
    if prm is not None and prm.document is not None:
        out.extend(
            ("PRM scopes_supported", s) for s in str_list(prm.document.get("scopes_supported"))
        )
    bearer = bearer_challenge(ctx.mcp.challenges)
    if bearer is not None and bearer.get("scope"):
        out.extend(("WWW-Authenticate scope", s) for s in (bearer.get("scope") or "").split())
    return out


@check(
    id="MCPP-SCP01",
    title="Over-broad scopes advertised",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    revisions=revisions_from(SpecRevision.R2025_06_18),
    references=[R.MCP_AUTH_2025_11, R.MCP_SECURITY_BP, R.RFC6749_3_3],
    rationale="""Wildcard or administrative scopes (`*`, `admin`, `all`, `files:*`) defeat
        least privilege: every client gets a token able to do everything, and a stolen token
        is a full compromise. MCP's scope selection and step-up model assumes fine-grained
        scopes.""",
    remediation="""Split permissions into narrow scopes (e.g. `notes:read`, `notes:write`),
        advertise the minimum in the challenge, and use 403 `insufficient_scope` step-up for
        the rest.""",
)
def scp01(ctx: ScanContext) -> Iterator[Finding]:
    broad: dict[str, set[str]] = {}
    for source, scope in _resource_scopes(ctx):
        if is_broad(scope):
            broad.setdefault(scope, set()).add(source)
    for scope in sorted(broad):
        yield ctx.finding(
            "MCPP-SCP01",
            f"Scope {scope!r} is over-broad (advertised in {', '.join(sorted(broad[scope]))}).",
            key=scope,
            evidence=[Evidence(summary="scope", excerpt=scope)],
        )


@check(
    id="MCPP-SCP02",
    title="Challenge does not name the required scope",
    severity=Severity.LOW,
    revisions=revisions_from(SpecRevision.R2025_11_25),
    references=[R.MCP_AUTH_2025_11, R.RFC6750_3_1],
    rationale="""Since 2025-11-25 servers SHOULD include `scope` in the 401 challenge so
        clients request exactly what the operation needs, instead of every scope in
        `scopes_supported`.""",
    remediation="""Add `scope="<scopes>"` to the `WWW-Authenticate: Bearer` challenge.""",
)
def scp02(ctx: ScanContext) -> Iterator[Finding]:
    bearer = bearer_challenge(ctx.mcp.challenges)
    ex = ctx.mcp.unauth_exchange
    if ctx.mcp.auth_required and bearer is not None and not bearer.get("scope") and ex:
        yield ctx.finding(
            "MCPP-SCP02",
            "The Bearer challenge has no scope parameter.",
            evidence=[exchange_evidence(ex, "challenge", 0)],
        )


@check(
    id="MCPP-SCP04",
    title="Resource scopes unknown to the authorization server",
    severity=Severity.INFO,
    confidence=Confidence.MEDIUM,
    revisions=revisions_from(SpecRevision.R2025_06_18),
    references=[R.RFC9728, R.RFC8414],
    rationale="""Scopes the resource advertises but the authorization server does not list
        will fail at authorization time, or are silently ignored, so clients end up with
        tokens that cannot call the tools.""",
    remediation="""Keep PRM `scopes_supported` a subset of the authorization server's
        `scopes_supported` (when the AS publishes one).""",
)
def scp04(ctx: ScanContext) -> Iterator[Finding]:
    resource = {s for _, s in _resource_scopes(ctx)}
    for server, doc in auth_servers(ctx):
        known = str_list(doc.get("scopes_supported"))
        if not known:
            continue
        missing = sorted(resource - set(known))
        if missing:
            yield ctx.finding(
                "MCPP-SCP04",
                f"Scopes not listed by {server.issuer}: {', '.join(missing)}.",
                location=server.issuer,
            )
