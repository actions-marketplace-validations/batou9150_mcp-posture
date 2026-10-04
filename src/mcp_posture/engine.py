"""Scan orchestration: collect once per target, freeze the context, run every applicable check."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlsplit

import httpx

from mcp_posture import __version__
from mcp_posture.client import McpClient
from mcp_posture.context import AuthDiscovery, McpProbe, ScanContext, Target
from mcp_posture.discovery import bearer_challenge, discover_auth
from mcp_posture.models import (
    CheckMode,
    Confidence,
    Finding,
    Report,
    RevisionSource,
    Severity,
    SpecRevision,
    TargetResult,
    ToolInfo,
)
from mcp_posture.net import Fetcher, HttpExchange, NetSettings, TlsProbe, probe_tls
from mcp_posture.registry import ERROR_CHECK_ID, RegisteredCheck, load_all

log = logging.getLogger(__name__)

ERROR_PROBE_PATH = "/mcp-posture-nonexistent-path"
MAX_TLS_ORIGINS = 6

TransportFactory = Callable[[], httpx.AsyncBaseTransport]


@dataclass(frozen=True)
class ScanOptions:
    net: NetSettings = field(default_factory=NetSettings)
    spec: SpecRevision | None = None
    active: bool = False
    token: str | None = None
    enable: frozenset[str] = frozenset()
    disable: frozenset[str] = frozenset()
    concurrency: int = 4
    fail_on: Severity = Severity.HIGH
    tls_probe: bool = True
    transport_factory: TransportFactory | None = None
    post_process: Callable[[ScanContext, list[Finding]], list[Finding]] | None = None


def map_revision(version: str | None) -> SpecRevision | None:
    if version is None:
        return None
    if version == "2024-11-05":
        return SpecRevision.R2025_03_26
    return SpecRevision.parse(version)


def select_checks(options: ScanOptions) -> list[RegisteredCheck]:
    def matches(selectors: frozenset[str], c: RegisteredCheck) -> bool:
        names = (c.meta.id, c.meta.id.removeprefix("MCPP-"), c.meta.family, f"MCPP-{c.meta.family}")
        return any(s in names for s in selectors)

    out = []
    for check_id in sorted(load_all()):
        c = load_all()[check_id]
        if options.enable and not matches(options.enable, c):
            continue
        if matches(options.disable, c):
            continue
        out.append(c)
    return out


def run_checks(
    ctx: ScanContext, checks: Sequence[RegisteredCheck]
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    not_applicable: list[str] = []
    for c in checks:
        if c.meta.mode == "active" and not ctx.active:
            continue
        if not c.applies_to(ctx.revision):
            not_applicable.append(c.meta.id)
            continue
        try:
            findings.extend(c.fn(ctx))
        except Exception as e:  # a broken check must never abort the scan
            log.exception("check %s failed", c.meta.id)
            findings.append(
                Finding(
                    check_id=ERROR_CHECK_ID,
                    title="Check failed to run",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    target=ctx.url,
                    location=c.meta.id,
                    message=f"{c.meta.id} raised {type(e).__name__}: {e}",
                )
            )
    return findings, not_applicable


async def collect(
    target: Target, fetcher: Fetcher, options: ScanOptions
) -> tuple[ScanContext | None, str | None]:
    """Gather everything the checks need. Returns (context, unreachable_reason)."""
    mcp: McpProbe = await McpClient(fetcher, target.url, options.token).probe()
    if not any(ex.status is not None for ex in fetcher.log):
        first = fetcher.log[0] if fetcher.log else None
        return None, (first.error if first and first.error else "no response")

    negotiated = map_revision(mcp.negotiated_version)
    revision_source: RevisionSource
    if options.spec is not None:
        revision, revision_source = options.spec, "pinned"
    elif negotiated is not None:
        revision, revision_source = negotiated, "negotiated"
    else:
        revision, revision_source = SpecRevision.latest(), "default"

    bearer = bearer_challenge(mcp.challenges)
    challenge_url = bearer.get("resource_metadata") if bearer else None
    auth: AuthDiscovery = await discover_auth(
        fetcher,
        target.url,
        challenge_url,
        legacy_origin_as=revision == SpecRevision.R2025_03_26,
    )

    plain_http: list[HttpExchange] = []
    tls: list[TlsProbe] = []
    parts = urlsplit(target.url)
    if parts.scheme == "https":
        http_url = parts._replace(scheme="http", netloc=parts.hostname or "").geturl()
        plain_http.append(await fetcher.request("GET", http_url, follow_redirects=False))
        if options.tls_probe:
            for host, port in _tls_origins(target.url, auth):
                tls.append(
                    await probe_tls(
                        host,
                        port,
                        ca_bundle=options.net.ca_bundle,
                        allow_private=options.net.allow_private,
                        timeout=options.net.timeout,
                    )
                )
    error_probe = await fetcher.request(
        "GET", f"{target.origin}{ERROR_PROBE_PATH}", follow_redirects=False
    )
    ctx = ScanContext(
        target=target,
        revision=revision,
        revision_source=revision_source,
        active=options.active,
        token_provided=options.token is not None,
        mcp=mcp,
        auth=auth,
        exchanges=tuple(fetcher.log),
        tls=tuple(tls),
        plain_http=tuple(plain_http),
        error_probe=error_probe,
    )
    return ctx, None


def _tls_origins(url: str, auth: AuthDiscovery) -> list[tuple[str, int]]:
    urls = [url]
    if auth.prm is not None:
        urls.append(auth.prm.url)
    urls.extend(s.issuer for s in auth.authorization_servers)
    out: list[tuple[str, int]] = []
    for u in urls:
        p = urlsplit(u)
        if p.scheme == "https" and p.hostname:
            key = (p.hostname, p.port or 443)
            if key not in out:
                out.append(key)
    return out[:MAX_TLS_ORIGINS]


async def scan_target(target: Target, options: ScanOptions) -> TargetResult:
    transport = options.transport_factory() if options.transport_factory else None
    async with Fetcher(options.net, transport=transport) as fetcher:
        try:
            ctx, error = await collect(target, fetcher, options)
        except Exception as e:  # collection bugs surface as an unreachable target, not a crash
            log.exception("collection failed for %s", target.url)
            ctx, error = None, f"internal error during collection: {type(e).__name__}: {e}"
    if ctx is None:
        return TargetResult(
            target=target.url,
            name=target.name,
            source=target.source,
            reachable=False,
            error=error,
            spec_revision=options.spec or SpecRevision.latest(),
            revision_source="pinned" if options.spec else "default",
        )
    findings, not_applicable = run_checks(ctx, select_checks(options))
    if options.post_process is not None:
        findings = options.post_process(ctx, findings)
    # A fingerprint identifies a finding across runs; keep the first if a check repeats one.
    findings = list({f.fingerprint: f for f in reversed(findings)}.values())
    findings.sort(key=Finding.sort_key)
    return TargetResult(
        target=target.url,
        name=target.name,
        source=target.source,
        reachable=True,
        spec_revision=ctx.revision,
        revision_source=ctx.revision_source,
        transport=ctx.mcp.transport,
        auth_required=ctx.mcp.auth_required,
        findings=tuple(findings),
        not_applicable=tuple(not_applicable),
    )


async def scan(
    targets: Iterable[Target], options: ScanOptions, *, generated_at: datetime | None = None
) -> Report:
    sem = asyncio.Semaphore(max(1, options.concurrency))

    async def bounded(t: Target) -> TargetResult:
        async with sem:
            return await scan_target(t, options)

    unique = list({t.url: t for t in targets}.values())
    results = await asyncio.gather(*(bounded(t) for t in unique))
    mode: CheckMode = "active" if options.active else "passive"
    return Report(
        tool=ToolInfo(version=__version__),
        generated_at=generated_at,
        mode=mode,
        fail_on=options.fail_on,
        targets=tuple(sorted(results, key=lambda r: r.target)),
    )


EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_UNREACHABLE = 3


def exit_code(report: Report) -> int:
    """1 if any unsuppressed finding ≥ fail_on, else 3 if any target unreachable, else 0."""
    if any(f.severity.at_least(report.fail_on) for f in report.active_findings()):
        return EXIT_FINDINGS
    if any(not t.reachable for t in report.targets):
        return EXIT_UNREACHABLE
    return EXIT_OK
