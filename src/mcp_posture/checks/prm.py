"""PRM: OAuth 2.0 Protected Resource Metadata (RFC 9728)."""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

from mcp_posture.checks import _refs as R
from mcp_posture.checks._util import is_https, is_loopback_url, str_list
from mcp_posture.context import MetadataFetch, ScanContext, exchange_evidence, thaw
from mcp_posture.models import Evidence, Finding, Severity, SpecRevision, revisions_from
from mcp_posture.registry import check

PRM_REVISIONS = revisions_from(SpecRevision.R2025_06_18)


def _prm(ctx: ScanContext) -> MetadataFetch | None:
    return ctx.auth.prm


def _uses_oauth(ctx: ScanContext) -> bool:
    return ctx.mcp.auth_required or ctx.auth.prm is not None


@check(
    id="MCPP-PRM01",
    title="Protected Resource Metadata not found",
    severity=Severity.HIGH,
    revisions=PRM_REVISIONS,
    references=[R.RFC9728, R.MCP_AUTH_2025_06, R.MCP_AUTH_DISCOVERY_2026],
    rationale="""Since 2025-06-18, MCP servers that require authorization MUST implement RFC 9728
        so clients can discover the authorization server. Without PRM, compliant clients
        cannot start the OAuth flow.""",
    remediation="""Serve a JSON document at
        `/.well-known/oauth-protected-resource<path>` containing at least `resource`
        (the exact MCP URL) and `authorization_servers`.""",
)
def prm01(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.mcp.auth_required and ctx.auth.prm is None:
        tried = ", ".join(
            f"{f.url} → {f.exchange.status or f.exchange.error}" for f in ctx.auth.prm_fetches
        )
        yield ctx.finding(
            "MCPP-PRM01",
            "The server requires authorization but no PRM document was found.",
            evidence=[Evidence(summary="tried", excerpt=tried)],
        )


@check(
    id="MCPP-PRM02",
    title="Protected Resource Metadata malformed",
    severity=Severity.MEDIUM,
    revisions=PRM_REVISIONS,
    references=[R.RFC9728],
    rationale="""RFC 9728 §3.2: a successful response MUST be 200 with an `application/json`
        JSON object, and parameters with zero values MUST be omitted. Clients reject anything
        else.""",
    remediation="""Return `200 OK`, `Content-Type: application/json`, a JSON object, and omit
        empty arrays.""",
)
def prm02(ctx: ScanContext) -> Iterator[Finding]:
    for f in ctx.auth.prm_fetches:
        ex = f.exchange
        if f.variant == "www-authenticate" and not f.found:
            yield ctx.finding(
                "MCPP-PRM02",
                f"The PRM URL advertised in WWW-Authenticate does not serve a JSON object "
                f"(HTTP {ex.status or ex.error}).",
                location=f.url,
                key="advertised",
                evidence=[exchange_evidence(ex, "advertised PRM URL")],
            )
            continue
        if not f.found:
            continue
        problems = []
        if ex.content_type != "application/json":
            problems.append(f"content type {ex.content_type or 'missing'}")
        empty = [k for k, v in (f.document or {}).items() if v in ((), "", None)]
        if empty:
            problems.append(f"empty values for {', '.join(sorted(empty))}")
        if problems:
            yield ctx.finding(
                "MCPP-PRM02",
                f"{f.url}: {'; '.join(problems)}.",
                location=f.url,
                key="format",
                evidence=[exchange_evidence(ex, "PRM response")],
            )


def _expected_resources(f: MetadataFetch, server_url: str) -> set[str]:
    if f.variant == "root":
        p = urlsplit(server_url)
        return {server_url, f"{p.scheme}://{p.netloc}", f"{p.scheme}://{p.netloc}/"}
    return {server_url}


@check(
    id="MCPP-PRM03",
    title="PRM resource does not match the server URL",
    severity=Severity.HIGH,
    revisions=PRM_REVISIONS,
    references=[R.RFC9728_3_3, R.RFC8707, R.MCP_AUTH_2025_11],
    rationale="""RFC 9728 §3.3: `resource` MUST be identical (code point for code point) to
        the URL the client used, or the metadata MUST NOT be used. The same value is the
        RFC 8707 audience of issued tokens; a mismatch breaks clients or yields tokens with
        the wrong audience.""",
    remediation="""Set `resource` to the exact public URL of the MCP endpoint (scheme, host,
        port, path; same trailing slash convention), and use it as the token audience.""",
)
def prm03(ctx: ScanContext) -> Iterator[Finding]:
    for f in ctx.auth.prm_fetches:
        if f.document is None:
            continue
        resource = f.document.get("resource")
        if not isinstance(resource, str) or not resource:
            yield ctx.finding(
                "MCPP-PRM03",
                f"{f.url} has no `resource` (REQUIRED).",
                location=f.url,
            )
            continue
        expected = _expected_resources(f, ctx.url)
        if resource in expected:
            continue
        near = resource.rstrip("/") == ctx.url.rstrip("/")
        yield ctx.finding(
            "MCPP-PRM03",
            f"{f.url}: resource {resource!r} does not match {ctx.url!r}"
            + (" (trailing slash only)." if near else "."),
            location=f.url,
            severity=Severity.MEDIUM if near else Severity.HIGH,
            evidence=[Evidence(summary="resource", excerpt=resource)],
        )


@check(
    id="MCPP-PRM04",
    title="PRM lists no authorization server",
    severity=Severity.HIGH,
    revisions=PRM_REVISIONS,
    references=[R.MCP_AUTH_2025_06, R.RFC9728],
    rationale="""The MCP spec requires PRM to include `authorization_servers` with at least
        one issuer; otherwise clients have nowhere to obtain a token.""",
    remediation="""Add `"authorization_servers": ["https://<issuer>"]`.""",
)
def prm04(ctx: ScanContext) -> Iterator[Finding]:
    f = _prm(ctx)
    if (
        f is not None
        and f.document is not None
        and not str_list(f.document.get("authorization_servers"))
    ):
        yield ctx.finding(
            "MCPP-PRM04", f"{f.url} has no usable authorization_servers.", location=f.url
        )


@check(
    id="MCPP-PRM05",
    title="Authorization server issuer not HTTPS",
    severity=Severity.HIGH,
    revisions=PRM_REVISIONS,
    references=[R.RFC8414, R.MCP_AUTH_2025_11],
    rationale="""Issuer identifiers MUST use https (RFC 8414 §2) and all authorization server
        endpoints MUST be served over HTTPS (MCP authorization, communication security).""",
    remediation="""List only `https://` issuers in `authorization_servers`.""",
)
def prm05(ctx: ScanContext) -> Iterator[Finding]:
    f = _prm(ctx)
    if f is None or f.document is None:
        return
    for issuer in str_list(f.document.get("authorization_servers")):
        if not is_https(issuer):
            yield ctx.finding(
                "MCPP-PRM05",
                f"Authorization server {issuer!r} is not an https URL.",
                location=f.url,
                key=issuer,
                severity=Severity.MEDIUM if is_loopback_url(issuer) else Severity.HIGH,
            )


@check(
    id="MCPP-PRM06",
    title="Bearer tokens accepted in the query string",
    severity=Severity.HIGH,
    revisions=PRM_REVISIONS,
    references=[R.RFC6750, R.OAUTH21, R.MCP_AUTH_2025_03],
    rationale="""Tokens in URLs leak into logs, proxies and Referer headers. OAuth 2.1 and the
        MCP spec forbid them; RFC 6750 §2.3 says the method SHOULD NOT be used.""",
    remediation="""Remove `query` from `bearer_methods_supported` and ignore `access_token`
        query parameters on the resource server.""",
)
def prm06(ctx: ScanContext) -> Iterator[Finding]:
    f = _prm(ctx)
    if (
        f is not None
        and f.document is not None
        and "query" in str_list(f.document.get("bearer_methods_supported"))
    ):
        yield ctx.finding(
            "MCPP-PRM06",
            "bearer_methods_supported includes `query`.",
            location=f.url,
        )


@check(
    id="MCPP-PRM07",
    title="PRM does not list scopes",
    severity=Severity.LOW,
    revisions=PRM_REVISIONS,
    references=[R.RFC9728, R.MCP_AUTH_2025_11],
    rationale="""`scopes_supported` is RECOMMENDED; MCP clients fall back to it when the
        challenge carries no `scope`, to request least privilege.""",
    remediation="""List the scopes the server understands in `scopes_supported`.""",
)
def prm07(ctx: ScanContext) -> Iterator[Finding]:
    f = _prm(ctx)
    if (
        f is not None
        and f.document is not None
        and not str_list(f.document.get("scopes_supported"))
    ):
        yield ctx.finding("MCPP-PRM07", "scopes_supported is absent.", location=f.url)


@check(
    id="MCPP-PRM08",
    title="PRM resource has a fragment or query",
    severity=Severity.HIGH,
    revisions=PRM_REVISIONS,
    references=[R.RFC8707, R.RFC9728],
    rationale="""The resource identifier becomes the RFC 8707 `resource` parameter, which MUST
        NOT contain a fragment and SHOULD NOT contain a query.""",
    remediation="""Use a resource URL without `#fragment` and without `?query`.""",
)
def prm08(ctx: ScanContext) -> Iterator[Finding]:
    f = _prm(ctx)
    if f is None or f.document is None:
        return
    resource = f.document.get("resource")
    if not isinstance(resource, str):
        return
    p = urlsplit(resource)
    if "#" in resource:
        yield ctx.finding("MCPP-PRM08", f"resource {resource!r} has a fragment.", location=f.url)
    elif p.query:
        yield ctx.finding(
            "MCPP-PRM08",
            f"resource {resource!r} has a query component.",
            location=f.url,
            severity=Severity.LOW,
        )


def _b64json(segment: str) -> Any:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


@check(
    id="MCPP-PRM09",
    title="Unsafe signed_metadata",
    severity=Severity.MEDIUM,
    revisions=PRM_REVISIONS,
    references=[R.RFC9728],
    rationale="""Signed metadata takes precedence over plain values (RFC 9728 §2.2). It MUST be
        a JWS with an `iss` claim; `alg=none`, or claims that contradict the JSON, defeat its
        purpose.""",
    remediation="""Sign metadata with an asymmetric algorithm, include `iss`, and keep the
        signed claims identical to the plain document (or drop `signed_metadata`).""",
)
def prm09(ctx: ScanContext) -> Iterator[Finding]:
    f = _prm(ctx)
    if f is None or f.document is None:
        return
    jws = f.document.get("signed_metadata")
    if not isinstance(jws, str):
        return
    parts = jws.split(".")
    try:
        header, claims = _b64json(parts[0]), _b64json(parts[1])
    except (ValueError, IndexError, RecursionError):
        yield ctx.finding("MCPP-PRM09", "signed_metadata is not a decodable JWS.", location=f.url)
        return
    if not isinstance(header, dict) or not isinstance(claims, dict):
        yield ctx.finding("MCPP-PRM09", "signed_metadata is not a JSON JWS.", location=f.url)
        return
    problems = []
    if str(header.get("alg", "")).lower() == "none":
        problems.append("alg=none")
    if "iss" not in claims:
        problems.append("no iss claim")
    plain = thaw(f.document)
    diffs = sorted(k for k, v in claims.items() if k in plain and plain[k] != v)
    if diffs:
        problems.append(f"claims differ from the JSON document: {', '.join(diffs)}")
    if problems:
        yield ctx.finding("MCPP-PRM09", f"signed_metadata: {'; '.join(problems)}.", location=f.url)


@check(
    id="MCPP-PRM10",
    title="offline_access advertised by the resource",
    severity=Severity.LOW,
    revisions=revisions_from(SpecRevision.R2026_07_28),
    references=[R.MCP_AUTH_2026],
    rationale="""2026-07-28: MCP servers SHOULD NOT include `offline_access` in
        `scopes_supported` or challenges; refresh-token issuance is the client's and
        authorization server's decision, and advertising it nudges clients into long-lived
        credentials.""",
    remediation="""Remove `offline_access` from `scopes_supported`.""",
)
def prm10(ctx: ScanContext) -> Iterator[Finding]:
    f = _prm(ctx)
    if (
        f is not None
        and f.document is not None
        and "offline_access" in str_list(f.document.get("scopes_supported"))
    ):
        yield ctx.finding("MCPP-PRM10", "scopes_supported includes offline_access.", location=f.url)


@check(
    id="MCPP-PRM11",
    title="PRM variants disagree",
    severity=Severity.MEDIUM,
    revisions=PRM_REVISIONS,
    references=[R.RFC9728, R.MCP_AUTH_2025_11],
    rationale="""Clients pick the PRM from the challenge or from different well-known URLs.
        If those documents name different authorization servers, clients end up in different
        trust domains (and a stale copy may point to a decommissioned issuer).""",
    remediation="""Serve a single PRM and make every variant (challenge URL, path-inserted,
        root) return the same authorization servers.""",
)
def prm11(ctx: ScanContext) -> Iterator[Finding]:
    found = [f for f in ctx.auth.prm_fetches if f.document is not None]
    sets = {
        f.url: tuple(sorted(str_list(f.document.get("authorization_servers"))))
        for f in found
        if f.document is not None
    }
    if len(set(sets.values())) > 1:
        detail = "; ".join(f"{u} → {list(v)}" for u, v in sets.items())
        yield ctx.finding(
            "MCPP-PRM11",
            "PRM documents list different authorization servers.",
            evidence=[Evidence(summary="authorization_servers per URL", excerpt=detail)],
        )
