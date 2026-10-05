from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any

import pytest

from mcp_posture.context import ScanContext, Target
from mcp_posture.engine import (
    EXIT_FINDINGS,
    EXIT_OK,
    EXIT_UNREACHABLE,
    ScanOptions,
    exit_code,
    map_revision,
    run_checks,
    scan,
    scan_target,
    select_checks,
)
from mcp_posture.models import Finding, Severity, SpecRevision
from mcp_posture.registry import RegisteredCheck, check, load_all
from tests.conftest import FAST_NET, ids, make_ctx, run_scan
from tests.fixtures.servers import MCP_HOST, MCP_URL, AsProfile, McpProfile, Router, router


def test_broken_check_becomes_error_finding() -> None:
    def boom(ctx: ScanContext) -> Iterator[Finding]:
        raise RuntimeError("kaboom")
        yield  # pragma: no cover

    meta = load_all()["MCPP-TRN01"].meta.model_copy(update={"id": "MCPP-TST01"})
    findings, na = run_checks(make_ctx(), [RegisteredCheck(meta=meta, fn=boom)])
    [f] = findings
    assert f.check_id == "MCPP-ERR00" and f.location == "MCPP-TST01" and "kaboom" in f.message
    assert na == []


def test_active_checks_skipped_in_passive_mode() -> None:
    meta = load_all()["MCPP-TRN01"].meta.model_copy(update={"id": "MCPP-TST02", "mode": "active"})
    called = []

    def fn(ctx: ScanContext) -> Iterator[Finding]:
        called.append(1)
        return iter(())

    run_checks(make_ctx(), [RegisteredCheck(meta=meta, fn=fn)])
    assert called == []
    run_checks(make_ctx(active=True), [RegisteredCheck(meta=meta, fn=fn)])
    assert called == [1]


def test_registry_rejects_duplicates() -> None:
    load_all()
    with pytest.raises(ValueError, match="duplicate"):
        check(id="MCPP-TRN01", title="x", severity=Severity.LOW, rationale="r", remediation="m")


def test_enable_disable_selectors() -> None:
    only_prm = {c.meta.id for c in select_checks(ScanOptions(enable=frozenset({"PRM"})))}
    assert only_prm and all(i.startswith("MCPP-PRM") for i in only_prm)
    no_trn = {c.meta.id for c in select_checks(ScanOptions(disable=frozenset({"MCPP-TRN"})))}
    assert not any(i.startswith("MCPP-TRN") for i in no_trn)
    one = select_checks(ScanOptions(enable=frozenset({"MCPP-ASM04"})))
    assert [c.meta.id for c in one] == ["MCPP-ASM04"]
    short = select_checks(ScanOptions(enable=frozenset({"ASM04", "TRN08"})))
    assert [c.meta.id for c in short] == ["MCPP-ASM04", "MCPP-TRN08"]


def test_map_revision() -> None:
    assert map_revision("2024-11-05") == SpecRevision.R2025_03_26
    assert map_revision("2025-06-18") == SpecRevision.R2025_06_18
    assert map_revision("1999-01-01") is None and map_revision(None) is None


def test_findings_are_sorted_and_deterministic() -> None:
    profile = McpProfile(require_auth=False, headers={})
    a, b = run_scan(profile), run_scan(profile)
    assert a == b
    ranks = [f.severity.rank for f in a.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_scan_many_targets_dedupes_and_exit_codes() -> None:
    options = ScanOptions(
        net=FAST_NET,
        tls_probe=False,
        transport_factory=router(McpProfile(require_auth=False)),
    )
    targets = [Target(MCP_URL), Target(MCP_URL), Target("https://down.test/mcp")]
    report = asyncio.run(scan(targets, options))
    assert [t.target for t in report.targets] == ["https://down.test/mcp", MCP_URL]
    assert report.summary.unreachable == 1
    assert exit_code(report) == EXIT_FINDINGS  # AUTHN01 is high
    relaxed = report.model_copy(update={"fail_on": Severity.CRITICAL})
    assert exit_code(relaxed) == EXIT_UNREACHABLE
    up = report.model_copy(update={"fail_on": Severity.CRITICAL, "targets": report.targets[1:]})
    assert exit_code(up) == EXIT_OK


def test_secure_fixture_has_only_informational_findings() -> None:
    result = run_scan(McpProfile(), AsProfile())
    assert {f.severity for f in result.findings} <= {Severity.INFO}
    assert ids(result) == {"MCPP-ASM08", "MCPP-CIMD02"}


def test_checks_never_emit_duplicate_fingerprints() -> None:
    """Dedup in the engine is a safety net; checks themselves must key repeated findings."""
    import scripts.demo_servers as demo
    from tests.fixtures.servers import Router, as_app, mcp_app

    base = "https://mcp.test"
    profile = demo.misconfigured(base)
    seen: list[str] = []

    def keep(ctx: ScanContext, findings: list[Finding]) -> list[Finding]:
        seen.extend(f.fingerprint for f in findings)
        return findings

    run_scan(
        transport=lambda: Router({base: mcp_app(profile), "https://as.test": as_app(AsProfile())}),
        url=f"{base}/mcp",
        post_process=keep,
    )
    assert seen and len(seen) == len(set(seen))


def test_target_timeout_bounds_a_slow_target() -> None:
    """Each request is bounded; the whole collection of one target is bounded too."""

    async def slow(scope: Any, receive: Any, send: Any) -> None:
        await asyncio.sleep(10)

    opts = ScanOptions(
        net=FAST_NET,
        tls_probe=False,
        target_timeout=0.3,
        transport_factory=lambda: Router({f"https://{MCP_HOST}": slow}),
    )
    result = asyncio.run(scan_target(Target(url=MCP_URL), opts))
    assert not result.reachable
    assert result.error == "scan of this target exceeded 0.3s"
