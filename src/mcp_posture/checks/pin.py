"""PIN: rug-pull detection against a ``--baseline`` lock file."""

from __future__ import annotations

from collections.abc import Iterator, Mapping

from mcp_posture.checks import _refs as R
from mcp_posture.context import ScanContext
from mcp_posture.heuristics import visible
from mcp_posture.models import Evidence, Finding, Severity
from mcp_posture.pin import Lock, LockItem, diff_surface
from mcp_posture.registry import check


def _baseline(ctx: ScanContext) -> tuple[Lock | None, Mapping[str, LockItem] | None]:
    lock = ctx.extras.get("baseline")
    if not isinstance(lock, Lock):
        return None, None
    return lock, lock.targets.get(ctx.url)


def _diff(ctx: ScanContext):  # type: ignore[no-untyped-def]
    _, pinned = _baseline(ctx)
    if pinned is None or not ctx.mcp.surface_listed:
        return None
    return diff_surface(pinned, ctx.mcp.surface)


_REMEDIATION = """If the change is expected (you updated the server), review the diff and
    refresh the lock file with `mcp-posture pin`. If not, stop using the server: definitions
    that change after approval are how rug pulls work."""


@check(
    id="MCPP-PIN01",
    title="Tool surface item added since the baseline",
    severity=Severity.MEDIUM,
    references=[R.MCP_SECURITY_BP, R.OWASP_MCP_TOP10],
    rationale="""A new tool, prompt or resource appeared after the server was reviewed and
        pinned. New tools are exposed to the agent without any review.""",
    remediation=_REMEDIATION,
)
def pin01(ctx: ScanContext) -> Iterator[Finding]:
    d = _diff(ctx)
    for loc in d.added if d else ():
        yield ctx.finding("MCPP-PIN01", f"{loc} is not in the baseline.", location=loc)


@check(
    id="MCPP-PIN02",
    title="Tool surface item removed since the baseline",
    severity=Severity.LOW,
    references=[R.MCP_SECURITY_BP],
    rationale="""A pinned item disappeared. Usually benign, but a removal paired with an
        addition can be a rename used to slip a different definition past review.""",
    remediation=_REMEDIATION,
)
def pin02(ctx: ScanContext) -> Iterator[Finding]:
    d = _diff(ctx)
    for loc in d.removed if d else ():
        yield ctx.finding("MCPP-PIN02", f"{loc} disappeared.", location=loc)


@check(
    id="MCPP-PIN03",
    title="Tool definition changed since the baseline (rug pull)",
    severity=Severity.HIGH,
    references=[R.MCP_SECURITY_BP, R.OWASP_MCP_TOP10],
    rationale="""The description, schema or annotations of a pinned item changed. A server
        can pass review with a benign description and swap it later; the agent reads the new
        text on the next session without the user noticing.""",
    remediation=_REMEDIATION,
)
def pin03(ctx: ScanContext) -> Iterator[Finding]:
    d = _diff(ctx)
    for c in d.changed if d else ():
        yield ctx.finding(
            "MCPP-PIN03",
            f"{c.location} changed: {', '.join(c.fields) or 'duplicate definition'}.",
            location=c.location,
            key=c.hash,
            evidence=[Evidence(summary="diff against the baseline", excerpt=visible(c.diff))],
        )


@check(
    id="MCPP-PIN04",
    title="Target not covered by the baseline",
    severity=Severity.INFO,
    references=[R.MCP_SECURITY_BP],
    rationale="""A baseline was given but cannot be compared for this target: it is not
        pinned, or its tool surface could not be listed (authentication required and no
        token supplied).""",
    remediation="""Pin the target with `mcp-posture pin <url>`, or supply a token so the tool
        surface can be listed.""",
)
def pin04(ctx: ScanContext) -> Iterator[Finding]:
    lock, pinned = _baseline(ctx)
    if lock is None:
        return
    if pinned is None:
        yield ctx.finding("MCPP-PIN04", "The target is not in the baseline.", key="missing")
    elif not ctx.mcp.surface_listed:
        yield ctx.finding(
            "MCPP-PIN04",
            "The tool surface could not be listed, so the baseline was not compared.",
            key="unlisted",
        )
