"""ASM: OAuth 2.0 Authorization Server Metadata (RFC 8414) / OpenID Connect Discovery."""

from __future__ import annotations

from collections.abc import Iterator
from urllib.parse import urlsplit

from mcp_posture.checks import _refs as R
from mcp_posture.checks._util import (
    auth_servers,
    field_evidence,
    is_https,
    is_loopback_url,
    str_list,
)
from mcp_posture.context import ScanContext, exchange_evidence
from mcp_posture.models import (
    Confidence,
    Evidence,
    Finding,
    Severity,
    SpecRevision,
    revisions_from,
)
from mcp_posture.registry import check

ENDPOINT_FIELDS = (
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "registration_endpoint",
    "jwks_uri",
    "revocation_endpoint",
    "introspection_endpoint",
    "userinfo_endpoint",
    "pushed_authorization_request_endpoint",
    "device_authorization_endpoint",
)
NO_NONE_ALG_FIELDS = (
    "token_endpoint_auth_signing_alg_values_supported",
    "revocation_endpoint_auth_signing_alg_values_supported",
    "introspection_endpoint_auth_signing_alg_values_supported",
)


@check(
    id="MCPP-ASM01",
    title="Authorization server metadata not found",
    severity=Severity.HIGH,
    revisions=revisions_from(SpecRevision.R2025_06_18),
    references=[R.RFC8414, R.OIDC_DISCOVERY, R.MCP_AUTH_2025_11],
    rationale="""MCP authorization servers MUST publish RFC 8414 metadata (or, since
        2025-11-25, OpenID Connect Discovery). Clients cannot learn the endpoints or verify
        PKCE support otherwise.""",
    remediation="""Publish `/.well-known/oauth-authorization-server` (path-inserted for issuers
        with a path) or `/.well-known/openid-configuration`.""",
)
def asm01(ctx: ScanContext) -> Iterator[Finding]:
    for s in ctx.auth.authorization_servers:
        if s.document is None:
            tried = ", ".join(
                f"{f.url} → {f.exchange.status or f.exchange.error}" for f in s.fetches
            )
            yield ctx.finding(
                "MCPP-ASM01",
                f"No metadata found for issuer {s.issuer}.",
                location=s.issuer,
                evidence=[Evidence(summary="tried", excerpt=tried)],
            )


@check(
    id="MCPP-ASM02",
    title="Issuer mismatch",
    severity=Severity.HIGH,
    references=[R.RFC8414_3_3, R.OIDC_DISCOVERY, R.MCP_AUTH_DISCOVERY_2026],
    rationale="""The `issuer` in the metadata MUST be identical to the issuer used to build the
        well-known URL; otherwise the metadata MUST NOT be used. A mismatch is the classic
        authorization-server impersonation / mix-up setup.""",
    remediation="""Make `issuer` exactly equal to the value listed in `authorization_servers`
        (same scheme, host, port, path, trailing slash), https, without query or fragment.""",
)
def asm02(ctx: ScanContext) -> Iterator[Finding]:
    for s, doc in auth_servers(ctx):
        issuer = doc.get("issuer")
        loc = s.metadata.url if s.metadata else s.issuer
        if not isinstance(issuer, str):
            yield ctx.finding("MCPP-ASM02", f"{loc} has no issuer.", location=loc)
            continue
        p = urlsplit(issuer)
        if p.query or p.fragment:
            yield ctx.finding(
                "MCPP-ASM02",
                f"issuer {issuer!r} has a query or fragment.",
                location=loc,
                key="shape",
            )
        if issuer != s.issuer and not (
            s.metadata and s.metadata.variant == "legacy-origin" and issuer.rstrip("/") == s.issuer
        ):
            yield ctx.finding(
                "MCPP-ASM02",
                f"Metadata at {loc} declares issuer {issuer!r}, expected {s.issuer!r}.",
                location=loc,
                evidence=field_evidence(s, "issuer"),
            )


@check(
    id="MCPP-ASM03",
    title="Authorization server endpoint not HTTPS",
    severity=Severity.HIGH,
    references=[R.RFC8414, R.MCP_AUTH_2025_11],
    rationale="""All authorization server endpoints MUST be served over HTTPS (MCP
        authorization, communication security). Codes, tokens and client credentials would
        otherwise travel in clear text.""",
    remediation="""Publish only `https://` endpoint URLs.""",
)
def asm03(ctx: ScanContext) -> Iterator[Finding]:
    for s, doc in auth_servers(ctx):
        for name in ENDPOINT_FIELDS:
            url = doc.get(name)
            if isinstance(url, str) and not is_https(url):
                yield ctx.finding(
                    "MCPP-ASM03",
                    f"{name} is not HTTPS: {url}.",
                    location=s.issuer,
                    key=name,
                    severity=Severity.MEDIUM if is_loopback_url(url) else Severity.HIGH,
                )


@check(
    id="MCPP-ASM04",
    title="PKCE S256 not advertised",
    severity=Severity.CRITICAL,
    references=[R.RFC7636, R.OAUTH21, R.RFC9700, R.MCP_AUTH_2025_11],
    rationale="""PKCE is mandatory for MCP clients, and since 2025-11-25 clients MUST refuse to
        proceed when `code_challenge_methods_supported` is absent. Without S256, authorization
        codes can be intercepted and redeemed by an attacker.""",
    remediation="""Enforce PKCE and advertise `"code_challenge_methods_supported": ["S256"]`.""",
)
def asm04(ctx: ScanContext) -> Iterator[Finding]:
    for s, doc in auth_servers(ctx):
        methods = str_list(doc.get("code_challenge_methods_supported"))
        if "code_challenge_methods_supported" not in doc:
            msg = "code_challenge_methods_supported is absent (PKCE support not advertised)."
        elif "S256" not in methods:
            msg = f"code_challenge_methods_supported {methods} does not include S256."
        else:
            continue
        yield ctx.finding(
            "MCPP-ASM04",
            msg,
            location=s.issuer,
            evidence=field_evidence(s, "code_challenge_methods_supported"),
        )


@check(
    id="MCPP-ASM05",
    title="PKCE plain method allowed",
    severity=Severity.HIGH,
    references=[R.RFC7636, R.OAUTH21, R.RFC9700],
    rationale="""The `plain` transformation sends the verifier in the authorization request,
        which defeats PKCE against an attacker who can read it, and allows downgrade.
        OAuth 2.1 prohibits it.""",
    remediation="""Advertise and accept only `S256`.""",
)
def asm05(ctx: ScanContext) -> Iterator[Finding]:
    for s, doc in auth_servers(ctx):
        if "plain" in str_list(doc.get("code_challenge_methods_supported")):
            yield ctx.finding(
                "MCPP-ASM05",
                "code_challenge_methods_supported includes plain.",
                location=s.issuer,
                evidence=field_evidence(s, "code_challenge_methods_supported"),
            )


@check(
    id="MCPP-ASM06",
    title="Deprecated grant types enabled",
    severity=Severity.HIGH,
    references=[R.OAUTH21, R.RFC9700, R.RFC8414],
    rationale="""OAuth 2.1 removes the implicit and resource owner password grants; RFC 9700
        says the password grant MUST NOT be used. When `grant_types_supported` is omitted,
        RFC 8414 defaults it to authorization_code and implicit.""",
    remediation="""Disable implicit and password grants and list the supported grants
        explicitly, e.g. `["authorization_code", "refresh_token"]`.""",
)
def asm06(ctx: ScanContext) -> Iterator[Finding]:
    for s, doc in auth_servers(ctx):
        if "grant_types_supported" not in doc:
            yield ctx.finding(
                "MCPP-ASM06",
                "grant_types_supported is omitted, so the RFC 8414 default includes implicit.",
                location=s.issuer,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                key="default",
            )
            continue
        bad = [
            g for g in str_list(doc.get("grant_types_supported")) if g in ("implicit", "password")
        ]
        if bad:
            yield ctx.finding(
                "MCPP-ASM06",
                f"grant_types_supported includes {', '.join(bad)}.",
                location=s.issuer,
                evidence=field_evidence(s, "grant_types_supported"),
            )


@check(
    id="MCPP-ASM07",
    title="Response types incompatible with OAuth 2.1",
    severity=Severity.MEDIUM,
    references=[R.OAUTH21, R.RFC8414],
    rationale="""MCP uses the authorization code flow, so `code` must be supported; response
        types returning an access token from the authorization endpoint (`token`) are the
        implicit flow, removed in OAuth 2.1.""",
    remediation="""Support `code`; remove response types containing `token`.""",
)
def asm07(ctx: ScanContext) -> Iterator[Finding]:
    for s, doc in auth_servers(ctx):
        types = str_list(doc.get("response_types_supported"))
        if "code" not in types:
            yield ctx.finding(
                "MCPP-ASM07",
                f"response_types_supported {types} does not include code.",
                location=s.issuer,
                key="code",
                evidence=field_evidence(s, "response_types_supported"),
            )
        implicit = [t for t in types if "token" in t.split()]
        if implicit:
            yield ctx.finding(
                "MCPP-ASM07",
                f"response_types_supported includes {', '.join(implicit)}.",
                location=s.issuer,
                key="token",
                evidence=field_evidence(s, "response_types_supported"),
            )


@check(
    id="MCPP-ASM08",
    title="Resource indicator (RFC 8707) enforcement not verified",
    severity=Severity.INFO,
    confidence=Confidence.LOW,
    revisions=revisions_from(SpecRevision.R2025_06_18),
    references=[R.RFC8707, R.MCP_AUTH_2025_06],
    rationale="""Audience-restricted tokens are what stops a token minted for one MCP server
        being replayed against another. No metadata field advertises RFC 8707 support, so a
        passive scan cannot confirm it.""",
    remediation="""Ensure the authorization server honors `resource` and sets `aud`, and that
        the MCP server rejects tokens for other audiences. Run `--active` (ACT06, ACT03) to
        verify.""",
)
def asm08(ctx: ScanContext) -> Iterator[Finding]:
    if ctx.active:
        return
    for s, _doc in auth_servers(ctx):
        yield ctx.finding(
            "MCPP-ASM08",
            "Audience restriction cannot be verified passively; run with --active.",
            location=s.issuer,
        )


@check(
    id="MCPP-ASM09",
    title="Dynamic Client Registration endpoint exposed",
    severity=Severity.INFO,
    references=[R.RFC7591, R.MCP_CLIENT_REG_2026],
    rationale="""Anonymous DCR lets anyone create clients (with arbitrary names, logos and
        redirect URIs) that users will see on consent screens. It is allowed but worth knowing,
        especially since 2026-07-28 deprecates DCR for MCP.""",
    remediation="""If DCR is not needed, disable it. Otherwise rate-limit it, require an initial
        access token where possible, and show the redirect hostname on consent.""",
)
def asm09(ctx: ScanContext) -> Iterator[Finding]:
    for s, doc in auth_servers(ctx):
        endpoint = doc.get("registration_endpoint")
        if isinstance(endpoint, str):
            yield ctx.finding(
                "MCPP-ASM09",
                f"registration_endpoint advertised: {endpoint}.",
                location=s.issuer,
            )


@check(
    id="MCPP-ASM10",
    title="Dynamic Client Registration without Client ID Metadata Documents",
    severity=Severity.LOW,
    revisions=revisions_from(SpecRevision.R2025_11_25),
    references=[R.MCP_AUTH_2025_11, R.MCP_CLIENT_REG_2026, R.CIMD_DRAFT],
    rationale="""Since 2025-11-25, CIMD is the recommended registration path (SHOULD) and DCR
        is optional; 2026-07-28 deprecates DCR. An AS offering only DCR keeps the open
        registration surface and gives clients no verifiable identity.""",
    remediation="""Enable Client ID Metadata Document support and advertise
        `client_id_metadata_document_supported: true`.""",
)
def asm10(ctx: ScanContext) -> Iterator[Finding]:
    for s, doc in auth_servers(ctx):
        if (
            "registration_endpoint" in doc
            and doc.get("client_id_metadata_document_supported") is not True
        ):
            yield ctx.finding(
                "MCPP-ASM10",
                "The authorization server offers DCR but not Client ID Metadata Documents.",
                location=s.issuer,
                severity=Severity.MEDIUM if ctx.revision.stateless else Severity.LOW,
            )


@check(
    id="MCPP-ASM11",
    title="Authorization response iss parameter not supported",
    severity=Severity.LOW,
    revisions=revisions_from(SpecRevision.R2025_06_18),
    references=[R.RFC9207, R.RFC9700, R.MCP_AUTH_SECURITY_2026],
    rationale="""RFC 9207 `iss` in authorization responses is the standard defence against
        mix-up attacks (RFC 9700 §2.1). 2026-07-28 makes it a SHOULD; it matters most when a
        resource lists several authorization servers.""",
    remediation="""Return `iss` in authorization responses and advertise
        `authorization_response_iss_parameter_supported: true`.""",
)
def asm11(ctx: ScanContext) -> Iterator[Finding]:
    servers = list(auth_servers(ctx))
    for s, doc in servers:
        if doc.get("authorization_response_iss_parameter_supported") is not True:
            yield ctx.finding(
                "MCPP-ASM11",
                "authorization_response_iss_parameter_supported is not true"
                + (
                    f" ({len(servers)} authorization servers: mix-up risk)."
                    if len(servers) > 1
                    else "."
                ),
                location=s.issuer,
                severity=Severity.MEDIUM if len(servers) > 1 else Severity.LOW,
            )


@check(
    id="MCPP-ASM12",
    title="Unsigned (alg=none) client authentication allowed",
    severity=Severity.MEDIUM,
    references=[R.RFC8414],
    rationale="""RFC 8414 §2: the value `none` MUST NOT be used in the signing algorithm lists
        for endpoint authentication; it would accept unsigned client assertions.""",
    remediation="""Remove `none` from the *_auth_signing_alg_values_supported lists.""",
)
def asm12(ctx: ScanContext) -> Iterator[Finding]:
    for s, doc in auth_servers(ctx):
        for name in NO_NONE_ALG_FIELDS:
            if "none" in [a.lower() for a in str_list(doc.get(name))]:
                yield ctx.finding(
                    "MCPP-ASM12", f"{name} includes none.", location=s.issuer, key=name
                )


@check(
    id="MCPP-ASM13",
    title="Default authorization endpoints without metadata (2025-03-26)",
    severity=Severity.MEDIUM,
    revisions=(SpecRevision.R2025_03_26,),
    references=[R.MCP_AUTH_2025_03, R.RFC8414],
    rationale="""In 2025-03-26 the MCP server is its own authorization server; without RFC 8414
        metadata, clients guess `/authorize`, `/token` and `/register` and cannot verify PKCE
        support or endpoint policy.""",
    remediation="""Publish `/.well-known/oauth-authorization-server` at the server origin, or
        move to the 2025-06-18+ model with a separate authorization server and PRM.""",
)
def asm13(ctx: ScanContext) -> Iterator[Finding]:
    legacy = ctx.auth.legacy_as
    if legacy is None or legacy.document is not None or not ctx.mcp.auth_required:
        return
    live = [ex for ex in ctx.auth.legacy_fallback_endpoints if ex.status not in (None, 404)]
    yield ctx.finding(
        "MCPP-ASM13",
        "No authorization server metadata at the origin"
        + (f"; {len(live)} default endpoint(s) respond." if live else "."),
        location=legacy.issuer,
        evidence=[exchange_evidence(ex, "default endpoint", 0) for ex in live],
    )
