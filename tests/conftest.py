"""Shared helpers for tests."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from mcp_posture.context import AuthDiscovery, McpProbe, ScanContext, Target
from mcp_posture.engine import ScanOptions, scan_target
from mcp_posture.models import Finding, SpecRevision, TargetResult
from mcp_posture.net import NetSettings
from mcp_posture.registry import load_all
from tests.fixtures.servers import MCP_URL, AsProfile, McpProfile, Router, router

FAST_NET = NetSettings(timeout=2.0, retries=0)


def run_scan(
    mcp: McpProfile | None = None,
    auth: AsProfile | None = None,
    *,
    url: str = MCP_URL,
    transport: Callable[[], Router] | None = None,
    http_listener: bool = False,
    **options: object,
) -> TargetResult:
    opts = ScanOptions(
        net=FAST_NET,
        tls_probe=False,
        transport_factory=transport or router(mcp, auth, http_listener=http_listener),
        **options,  # type: ignore[arg-type]
    )
    return asyncio.run(scan_target(Target(url=url), opts))


def ids(result: TargetResult) -> set[str]:
    return {f.check_id for f in result.findings}


def by_id(result: TargetResult, check_id: str) -> list[Finding]:
    return [f for f in result.findings if f.check_id == check_id]


def make_ctx(**overrides: object) -> ScanContext:
    """A minimal context for unit-testing a single check."""
    base: dict[str, object] = {
        "target": Target(url=MCP_URL),
        "revision": SpecRevision.R2026_07_28,
        "revision_source": "default",
        "active": False,
        "token_provided": False,
        "mcp": McpProbe(),
        "auth": AuthDiscovery(),
        "exchanges": (),
    }
    base.update(overrides)
    return ScanContext(**base)  # type: ignore[arg-type]


def run_check(check_id: str, ctx: ScanContext) -> list[Finding]:
    return list(load_all()[check_id].fn(ctx))
