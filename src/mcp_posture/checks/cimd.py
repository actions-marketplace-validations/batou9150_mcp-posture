"""CIMD: Client ID Metadata Documents (passive checks)."""

from __future__ import annotations

from collections.abc import Iterator

from mcp_posture.checks import _refs as R
from mcp_posture.checks._util import auth_servers
from mcp_posture.context import ScanContext
from mcp_posture.models import Evidence, Finding, Severity, SpecRevision, revisions_from
from mcp_posture.registry import check

CIMD_REVISIONS = revisions_from(SpecRevision.R2025_11_25)


@check(
    id="MCPP-CIMD01",
    title="Client ID Metadata Documents not advertised",
    severity=Severity.LOW,
    revisions=CIMD_REVISIONS,
    references=[R.MCP_AUTH_2025_11, R.MCP_CLIENT_REG_2026, R.CIMD_DRAFT],
    rationale="""Since 2025-11-25 authorization servers SHOULD support CIMD, and CIMD-capable
        servers MUST say so with `client_id_metadata_document_supported`. Without it, MCP
        clients fall back to DCR or manual pre-registration.""",
    remediation="""Implement CIMD (fetch the client_id URL, validate per the draft's §4-§8)
        and advertise `client_id_metadata_document_supported: true`.""",
)
def cimd01(ctx: ScanContext) -> Iterator[Finding]:
    for s, doc in auth_servers(ctx):
        if doc.get("client_id_metadata_document_supported") is not True:
            yield ctx.finding(
                "MCPP-CIMD01",
                "client_id_metadata_document_supported is not true.",
                location=s.issuer,
            )


def registration_strategies(doc: object) -> list[str]:
    from collections.abc import Mapping

    if not isinstance(doc, Mapping):
        return []
    out = []
    if doc.get("client_id_metadata_document_supported") is True:
        out.append("CIMD")
    if isinstance(doc.get("registration_endpoint"), str):
        out.append("DCR")
    out.append("pre-registration")
    return out


@check(
    id="MCPP-CIMD02",
    title="Client registration strategies",
    severity=Severity.INFO,
    references=[R.MCP_CLIENT_REG_2026],
    rationale="""MCP clients try pre-registration, then CIMD, then DCR. Knowing which paths an
        authorization server offers explains how (and whether) arbitrary MCP clients can
        connect.""",
    remediation="""Informational. Prefer CIMD; keep DCR only for backwards compatibility.""",
)
def cimd02(ctx: ScanContext) -> Iterator[Finding]:
    for s, doc in auth_servers(ctx):
        strategies = registration_strategies(doc)
        yield ctx.finding(
            "MCPP-CIMD02",
            f"Registration paths offered: {', '.join(strategies)}.",
            location=s.issuer,
            evidence=[Evidence(summary="strategies", excerpt=", ".join(strategies))],
        )
