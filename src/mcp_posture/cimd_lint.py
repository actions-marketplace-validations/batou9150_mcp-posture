"""``mcp-posture cimd lint``: validate a client's own Client ID Metadata Document.

Rules follow draft-ietf-oauth-client-id-metadata-document-02 and the MCP client
registration requirements. They are catalogued as MCPP-CIMD5x (mode ``lint``) and never run
during ``scan``.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from mcp_posture.checks import _refs as R
from mcp_posture.models import (
    CheckMeta,
    Confidence,
    Evidence,
    Finding,
    Reference,
    Severity,
    SpecRevision,
    revisions_from,
)
from mcp_posture.net import HttpExchange, is_loopback_host

MAX_DOCUMENT_BYTES = 5 * 1024
SHARED_SECRET_METHODS = frozenset(
    {"client_secret_post", "client_secret_basic", "client_secret_jwt"}
)
PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
LOOPBACK_HOSTS = ("127.0.0.1", "[::1]", "localhost")


@dataclass(frozen=True)
class LintInput:
    """A document to lint: from a URL (with the HTTP exchange) or from a file."""

    source: str
    document: Mapping[str, Any] | None
    client_id_url: str | None
    exchange: HttpExchange | None = None
    raw_size: int = 0
    parse_error: str | None = None


LintFn = Callable[[LintInput], Iterator[Finding]]


@dataclass(frozen=True)
class LintRule:
    meta: CheckMeta
    fn: LintFn


LINT_RULES: dict[str, LintRule] = {}


def rule(
    *,
    id: str,
    title: str,
    severity: Severity,
    rationale: str,
    remediation: str,
    references: list[tuple[str, str]],
    confidence: Confidence = Confidence.HIGH,
) -> Callable[[LintFn], LintFn]:
    meta = CheckMeta(
        id=id,
        family="CIMD",
        title=title,
        severity=severity,
        confidence=confidence,
        revisions=revisions_from(SpecRevision.R2025_11_25),
        references=tuple(Reference(title=t, url=u) for t, u in references),
        rationale=" ".join(line.strip() for line in rationale.strip().splitlines()),
        remediation=" ".join(line.strip() for line in remediation.strip().splitlines()),
        mode="lint",
    )

    def decorator(fn: LintFn) -> LintFn:
        if id in LINT_RULES:
            raise ValueError(f"duplicate lint rule {id}")
        LINT_RULES[id] = LintRule(meta, fn)
        return fn

    return decorator


def _finding(
    inp: LintInput,
    rule_id: str,
    message: str,
    *,
    key: str = "",
    severity: Severity | None = None,
    evidence: tuple[Evidence, ...] = (),
) -> Finding:
    meta = LINT_RULES[rule_id].meta
    return Finding(
        check_id=rule_id,
        title=meta.title,
        severity=severity or meta.severity,
        confidence=meta.confidence,
        target=inp.source,
        location=inp.client_id_url or inp.source,
        message=message,
        key=key,
        evidence=evidence,
    )


def url_problems(url: str) -> list[str]:
    """Client identifier URL requirements (draft-02 §3)."""
    p = urlsplit(url)
    problems = []
    if p.scheme != "https":
        problems.append("scheme must be https")
    if not p.hostname:
        problems.append("no host")
    if p.username or p.password:
        problems.append("must not contain userinfo")
    if p.fragment or "#" in url:
        problems.append("must not contain a fragment")
    segments = p.path.split("/")
    if not p.path or p.path == "/":
        problems.append("must contain a path (a bare origin or '/' is not recommended)")
    if "." in segments or ".." in segments:
        problems.append("must not contain '.' or '..' path segments")
    if p.query:
        problems.append("should not contain a query component")
    if p.hostname and _is_ip(p.hostname):
        problems.append("uses an IP literal; authorization servers may refuse it")
    return problems


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


@rule(
    id="MCPP-CIMD50",
    title="Invalid client identifier URL",
    severity=Severity.HIGH,
    references=[R.CIMD_DRAFT, R.MCP_CLIENT_REG_2026],
    rationale="""The client_id of a CIMD client is a URL that authorization servers fetch
        and compare by simple string equality. It MUST be https with a path and MUST NOT
        contain userinfo, a fragment or dot segments; anything else is rejected or, worse,
        accepted inconsistently across servers.""",
    remediation="""Host the document at a stable https URL with a dedicated path, e.g.
        `https://app.example.com/oauth/client-metadata.json`, without query or fragment.""",
)
def cimd50(inp: LintInput) -> Iterator[Finding]:
    url = inp.client_id_url
    if url is None:
        return
    problems = url_problems(url)
    if problems:
        severity = Severity.LOW if problems == ["should not contain a query component"] else None
        yield _finding(inp, "MCPP-CIMD50", f"{url}: {'; '.join(problems)}.", severity=severity)


@rule(
    id="MCPP-CIMD51",
    title="Document client_id does not match its URL",
    severity=Severity.HIGH,
    references=[R.CIMD_DRAFT],
    rationale="""Authorization servers MUST reject a document whose client_id is not
        exactly the URL it was fetched from (simple string comparison: no normalization of
        case, default ports or trailing slashes).""",
    remediation="""Set `client_id` to the exact URL the document is served at.""",
)
def cimd51(inp: LintInput) -> Iterator[Finding]:
    if inp.document is None:
        return
    cid = inp.document.get("client_id")
    if not isinstance(cid, str) or not cid:
        yield _finding(inp, "MCPP-CIMD51", "client_id is missing.", key="missing")
    elif inp.client_id_url is not None and cid != inp.client_id_url:
        yield _finding(
            inp,
            "MCPP-CIMD51",
            f"client_id {cid!r} differs from the document URL {inp.client_id_url!r}.",
            evidence=(Evidence(summary="client_id", excerpt=cid),),
        )


@rule(
    id="MCPP-CIMD52",
    title="Required client metadata missing",
    severity=Severity.MEDIUM,
    references=[R.MCP_CLIENT_REG_2026, R.CIMD_DRAFT],
    rationale="""MCP requires client_id, client_name and redirect_uris in the document;
        authorization servers display client_name on consent and validate redirect_uri
        against redirect_uris.""",
    remediation="""Add a human-readable `client_name` and a non-empty `redirect_uris`
        array.""",
)
def cimd52(inp: LintInput) -> Iterator[Finding]:
    if inp.document is None:
        yield _finding(
            inp,
            "MCPP-CIMD52",
            f"No JSON object to validate ({inp.parse_error or 'empty document'}).",
            key="document",
            severity=Severity.HIGH,
        )
        return
    name = inp.document.get("client_name")
    if not isinstance(name, str) or not name.strip():
        yield _finding(inp, "MCPP-CIMD52", "client_name is missing or empty.", key="client_name")
    uris = inp.document.get("redirect_uris")
    if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
        yield _finding(
            inp,
            "MCPP-CIMD52",
            "redirect_uris must be a non-empty array of strings.",
            key="redirect_uris",
        )


def _redirect_problem(uri: str) -> str | None:
    p = urlsplit(uri)
    if "*" in uri:
        return "contains a wildcard"
    if p.fragment:
        return "contains a fragment"
    if p.scheme == "https":
        return None if p.hostname else "has no host"
    if p.scheme == "http":
        host = p.hostname or ""
        if is_loopback_host(host):
            return None
        return "uses plain http on a non-loopback host"
    if p.scheme in ("javascript", "data", "file", "vbscript"):
        return f"uses the dangerous scheme {p.scheme}:"
    if p.scheme and "." in p.scheme:
        return None  # private-use scheme (reverse domain), allowed for native apps
    return "uses an unexpected scheme" if p.scheme else "is not an absolute URI"


@rule(
    id="MCPP-CIMD53",
    title="Unsafe redirect URI",
    severity=Severity.MEDIUM,
    references=[R.CIMD_DRAFT, R.OAUTH21, R.RFC9700],
    rationale="""Authorization codes are delivered to the redirect URI. Plain-http
        non-loopback, wildcard, fragment or script URIs leak codes; loopback-only
        documents can be impersonated by any local app, which is why MCP asks authorization
        servers to warn on them.""",
    remediation="""Use https redirect URIs (or loopback for native apps with PKCE), with
        exact values, no wildcards and no fragments.""",
)
def cimd53(inp: LintInput) -> Iterator[Finding]:
    uris = inp.document.get("redirect_uris") if inp.document else None
    if not isinstance(uris, list):
        return
    strs = [u for u in uris if isinstance(u, str)]
    for uri in strs:
        problem = _redirect_problem(uri)
        if problem:
            yield _finding(inp, "MCPP-CIMD53", f"{uri} {problem}.", key=uri)
    if strs and all(is_loopback_host(urlsplit(u).hostname or "") for u in strs):
        yield _finding(
            inp,
            "MCPP-CIMD53",
            "All redirect URIs are loopback: any local application can claim this client "
            "identity; expect authorization servers to show impersonation warnings.",
            key="loopback-only",
            severity=Severity.INFO,
        )


@rule(
    id="MCPP-CIMD54",
    title="Shared secret in a public metadata document",
    severity=Severity.CRITICAL,
    references=[R.CIMD_DRAFT],
    rationale="""The document is public. Draft-02 §4.1 forbids client_secret,
        client_secret_expires_at and every shared-secret authentication method: a secret
        published at a URL is not a secret.""",
    remediation="""Remove the secret and rotate it now. Use `none` (public client with
        PKCE) or `private_key_jwt` with public keys in `jwks` / `jwks_uri`.""",
)
def cimd54(inp: LintInput) -> Iterator[Finding]:
    if inp.document is None:
        return
    for field in ("client_secret", "client_secret_expires_at"):
        if field in inp.document:
            yield _finding(inp, "MCPP-CIMD54", f"{field} is present.", key=field)
    method = inp.document.get("token_endpoint_auth_method")
    if isinstance(method, str) and method in SHARED_SECRET_METHODS:
        yield _finding(
            inp,
            "MCPP-CIMD54",
            f"token_endpoint_auth_method {method!r} relies on a shared secret.",
            key="method",
            severity=Severity.HIGH,
        )


@rule(
    id="MCPP-CIMD55",
    title="Private key material in the document",
    severity=Severity.CRITICAL,
    references=[R.CIMD_DRAFT],
    rationale="""Only public keys may be published. JWK members d, p, q, dp, dq, qi, oth
        (RSA/EC private parts) or k (symmetric) expose the key that authenticates the
        client.""",
    remediation="""Publish only public JWKs; rotate the exposed key immediately.""",
)
def cimd55(inp: LintInput) -> Iterator[Finding]:
    jwks = inp.document.get("jwks") if inp.document else None
    keys = jwks.get("keys") if isinstance(jwks, Mapping) else None
    if not isinstance(keys, list):
        return
    for i, key in enumerate(keys):
        if isinstance(key, Mapping):
            leaked = sorted(PRIVATE_JWK_MEMBERS & set(key))
            if leaked:
                kid = key.get("kid", i)
                yield _finding(
                    inp,
                    "MCPP-CIMD55",
                    f"jwks key {kid!r} contains private members {', '.join(leaked)}.",
                    key=str(kid),
                )


@rule(
    id="MCPP-CIMD56",
    title="Authentication method inconsistent with key material",
    severity=Severity.MEDIUM,
    references=[R.CIMD_DRAFT, R.RFC7591],
    rationale="""private_key_jwt needs public keys (jwks or jwks_uri) for the
        authorization server to verify assertions; RFC 7591 forbids sending both jwks and
        jwks_uri; keys published by a public client are unused and confusing.""",
    remediation="""For `private_key_jwt`, publish exactly one of `jwks` or `jwks_uri`
        (https). For a public client, use `none` and drop the keys.""",
)
def cimd56(inp: LintInput) -> Iterator[Finding]:
    doc = inp.document
    if doc is None:
        return
    method = doc.get("token_endpoint_auth_method", "client_secret_basic")
    has_jwks, has_uri = "jwks" in doc, "jwks_uri" in doc
    if has_jwks and has_uri:
        yield _finding(inp, "MCPP-CIMD56", "Both jwks and jwks_uri are present.", key="both")
    if method == "private_key_jwt" and not (has_jwks or has_uri):
        yield _finding(
            inp, "MCPP-CIMD56", "private_key_jwt without jwks or jwks_uri.", key="no-keys"
        )
    jwks_uri = doc.get("jwks_uri")
    if isinstance(jwks_uri, str) and urlsplit(jwks_uri).scheme != "https":
        yield _finding(inp, "MCPP-CIMD56", "jwks_uri is not https.", key="jwks_uri")
    if method == "none" and (has_jwks or has_uri):
        yield _finding(
            inp,
            "MCPP-CIMD56",
            "token_endpoint_auth_method is none but keys are published.",
            key="unused-keys",
            severity=Severity.INFO,
        )
    if "token_endpoint_auth_method" not in doc:
        yield _finding(
            inp,
            "MCPP-CIMD56",
            "token_endpoint_auth_method is omitted, so it defaults to client_secret_basic "
            "(a shared secret, not allowed for CIMD).",
            key="default",
            severity=Severity.HIGH,
        )


@rule(
    id="MCPP-CIMD57",
    title="Document not served the way authorization servers fetch it",
    severity=Severity.MEDIUM,
    references=[R.CIMD_DRAFT],
    rationale="""Authorization servers MUST treat any status other than 200 as an error,
        MUST NOT follow redirects, SHOULD cap the size (about 5 KB) and expect JSON.
        A document that only works through a redirect or is too large fails in
        production.""",
    remediation="""Serve the document directly (200, no redirect) as
        `application/json`, under 5 KB, with sensible `Cache-Control`.""",
)
def cimd57(inp: LintInput) -> Iterator[Finding]:
    ex = inp.exchange
    if ex is not None:
        if ex.status in (301, 302, 303, 307, 308):
            yield _finding(
                inp,
                "MCPP-CIMD57",
                f"The URL answers {ex.status} (redirect to {ex.header('location')}); "
                "authorization servers will not follow it.",
                key="redirect",
                severity=Severity.HIGH,
            )
        elif ex.status != 200:
            yield _finding(
                inp,
                "MCPP-CIMD57",
                f"The URL answers HTTP {ex.status or ex.error}.",
                key="status",
                severity=Severity.HIGH,
            )
        elif ex.content_type != "application/json":
            yield _finding(
                inp,
                "MCPP-CIMD57",
                f"Content-Type is {ex.content_type or 'missing'}, expected application/json.",
                key="content-type",
                severity=Severity.LOW,
            )
    if inp.raw_size > MAX_DOCUMENT_BYTES:
        yield _finding(
            inp,
            "MCPP-CIMD57",
            f"The document is {inp.raw_size} bytes; authorization servers may stop reading "
            f"at {MAX_DOCUMENT_BYTES}.",
            key="size",
        )


def parse_document(raw: bytes) -> tuple[Mapping[str, Any] | None, str | None]:
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        return None, f"invalid JSON: {e}"
    if not isinstance(doc, dict):
        return None, "the document is not a JSON object"
    return doc, None


def lint(inp: LintInput) -> list[Finding]:
    findings: list[Finding] = []
    for rule_id in sorted(LINT_RULES):
        findings.extend(LINT_RULES[rule_id].fn(inp))
    findings = list({f.fingerprint: f for f in reversed(findings)}.values())
    findings.sort(key=Finding.sort_key)
    return findings
