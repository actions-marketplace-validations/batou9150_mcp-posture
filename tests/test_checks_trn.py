from __future__ import annotations

import ssl
import time

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from mcp_posture.context import McpProbe, Target
from mcp_posture.models import Severity, SpecRevision
from mcp_posture.net import TlsProbe
from tests.conftest import by_id, ids, make_ctx, run_check, run_scan
from tests.fixtures.servers import (
    MCP_HOST,
    AsProfile,
    McpProfile,
    counter_sessions,
    router,
    static_sessions,
)


@pytest.mark.check("positive", "MCPP-TRN01")
def test_trn01_plain_http_endpoint() -> None:
    result = run_scan(McpProfile(), url=f"http://{MCP_HOST}/mcp", http_listener=True)
    [f] = by_id(result, "MCPP-TRN01")
    assert f.severity == Severity.CRITICAL


@pytest.mark.check("negative", "MCPP-TRN01")
def test_trn01_https_and_loopback_are_fine() -> None:
    assert "MCPP-TRN01" not in ids(run_scan(McpProfile()))
    ctx = make_ctx(target=Target("http://127.0.0.1/mcp"))
    assert run_check("MCPP-TRN01", ctx) == []


@pytest.mark.check("positive", "MCPP-TRN02")
def test_trn02_legacy_tls_accepted() -> None:
    ctx = make_ctx(
        tls=(TlsProbe("h", 443, verified=True, legacy_accepted=True, legacy_version="TLSv1.1"),)
    )
    [f] = run_check("MCPP-TRN02", ctx)
    assert "TLSv1.1" in f.message


@pytest.mark.check("negative", "MCPP-TRN02")
def test_trn02_modern_tls_only() -> None:
    for accepted in (False, None):
        ctx = make_ctx(tls=(TlsProbe("h", 443, verified=True, legacy_accepted=accepted),))
        assert run_check("MCPP-TRN02", ctx) == []


@pytest.mark.check("positive", "MCPP-TRN03")
def test_trn03_invalid_and_expiring_certificates() -> None:
    bad = TlsProbe("h", 443, verified=False, error="certificate verification failed: expired")
    soon = time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(time.time() + 5 * 86400))
    expiring = TlsProbe("e", 443, verified=True, not_after=soon)
    findings = run_check("MCPP-TRN03", make_ctx(tls=(bad, expiring)))
    assert [f.severity for f in findings] == [Severity.HIGH, Severity.LOW]


@pytest.mark.check("negative", "MCPP-TRN03")
def test_trn03_valid_certificate() -> None:
    later = time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(time.time() + 200 * 86400))
    ok = TlsProbe("h", 443, verified=True, not_after=later)
    garbage = TlsProbe("g", 443, verified=True, not_after="not a date")
    refused = TlsProbe("r", 443, verified=False, error="TLS handshake failed: refused")
    assert run_check("MCPP-TRN03", make_ctx(tls=(ok, garbage, refused))) == []
    assert ssl.cert_time_to_seconds(later) > time.time()


@pytest.mark.check("positive", "MCPP-TRN04")
def test_trn04_plain_http_serves_content() -> None:
    [f] = by_id(run_scan(McpProfile(), http_listener=True), "MCPP-TRN04")
    assert f.location == f"http://{MCP_HOST}/mcp"


@pytest.mark.check("negative", "MCPP-TRN04")
def test_trn04_redirect_or_closed_port() -> None:
    assert "MCPP-TRN04" not in ids(run_scan(McpProfile()))

    async def redirect(request: Request) -> Response:
        return RedirectResponse(str(request.url.replace(scheme="https")), status_code=308)

    app = Starlette(routes=[Route("/{p:path}", redirect)])
    transport = router(McpProfile(), extra={f"http://{MCP_HOST}": app})
    assert "MCPP-TRN04" not in ids(run_scan(transport=transport))


@pytest.mark.check("positive", "MCPP-TRN05")
def test_trn05_missing_hsts() -> None:
    result = run_scan(McpProfile(headers={"X-Content-Type-Options": "nosniff"}))
    assert by_id(result, "MCPP-TRN05")


@pytest.mark.check("negative", "MCPP-TRN05")
def test_trn05_hsts_present_or_http() -> None:
    assert "MCPP-TRN05" not in ids(run_scan(McpProfile()))
    http = run_scan(McpProfile(headers={}), url=f"http://{MCP_HOST}/mcp", http_listener=True)
    assert "MCPP-TRN05" not in ids(http)


@pytest.mark.check("positive", "MCPP-TRN06")
def test_trn06_legacy_sse_only() -> None:
    result = run_scan(McpProfile(revision="legacy-sse", require_auth=False))
    assert result.transport == "legacy-sse"
    [f] = by_id(result, "MCPP-TRN06")
    assert f.severity == Severity.MEDIUM
    pinned = run_scan(
        McpProfile(revision="legacy-sse", require_auth=False), spec=SpecRevision.R2025_03_26
    )
    assert by_id(pinned, "MCPP-TRN06")[0].severity == Severity.LOW


@pytest.mark.check("negative", "MCPP-TRN06")
def test_trn06_streamable_http() -> None:
    assert "MCPP-TRN06" not in ids(run_scan(McpProfile(require_auth=False)))


@pytest.mark.check("positive", "MCPP-TRN07")
def test_trn07_session_in_url() -> None:
    result = run_scan(McpProfile(revision="legacy-sse", require_auth=False))
    [f] = by_id(result, "MCPP-TRN07")
    assert "sessionId" in f.message


@pytest.mark.check("negative", "MCPP-TRN07")
def test_trn07_no_session_in_url() -> None:
    profile = McpProfile(revision="legacy-sse", require_auth=False, legacy_endpoint="/messages")
    assert "MCPP-TRN07" not in ids(run_scan(profile))
    assert "MCPP-TRN07" not in ids(run_scan(McpProfile(revision="2025-06-18", require_auth=False)))


@pytest.mark.check("positive", "MCPP-TRN08")
def test_trn08_sequential_and_short_session_ids() -> None:
    profile = McpProfile(revision="2025-06-18", require_auth=False, sessions=counter_sessions())
    result = run_scan(profile)
    keys = {f.key for f in by_id(result, "MCPP-TRN08")}
    assert keys == {"short", "sequential"}


@pytest.mark.check("positive", "MCPP-TRN08")
def test_trn08_static_and_non_ascii_session_ids() -> None:
    profile = McpProfile(
        revision="2025-11-25", require_auth=False, sessions=static_sessions("abc def" * 8)
    )
    keys = {f.key for f in by_id(run_scan(profile), "MCPP-TRN08")}
    assert keys == {"charset", "identical"}


@pytest.mark.check("negative", "MCPP-TRN08")
def test_trn08_random_session_ids() -> None:
    result = run_scan(McpProfile(revision="2025-06-18", require_auth=False))
    assert result.spec_revision == SpecRevision.R2025_06_18
    assert "MCPP-TRN08" not in ids(result)
    modern = run_scan(McpProfile(require_auth=False))
    assert "MCPP-TRN08" in modern.not_applicable


@pytest.mark.check("positive", "MCPP-TRN09")
def test_trn09_session_on_stateless_revision() -> None:
    result = run_scan(McpProfile(require_auth=False, modern_session_header=True))
    assert by_id(result, "MCPP-TRN09")


@pytest.mark.check("negative", "MCPP-TRN09")
def test_trn09_no_session_on_stateless_revision() -> None:
    assert "MCPP-TRN09" not in ids(run_scan(McpProfile(require_auth=False)))
    ctx = make_ctx(mcp=McpProbe(era="handshake", session_ids=("x",)))
    assert run_check("MCPP-TRN09", ctx) == []


@pytest.mark.check("positive", "MCPP-TRN10")
def test_trn10_weak_metadata_headers() -> None:
    auth = AsProfile(
        headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
    )
    findings = by_id(run_scan(McpProfile(), auth), "MCPP-TRN10")
    [f] = findings
    assert f.severity == Severity.MEDIUM
    assert "nosniff" in f.message


@pytest.mark.check("negative", "MCPP-TRN10")
def test_trn10_secure_metadata_headers() -> None:
    assert "MCPP-TRN10" not in ids(run_scan(McpProfile()))


def test_trn10_reports_a_redirected_metadata_variant_once() -> None:
    """The root PRM redirecting to the path-inserted one is one document, one finding."""
    from mcp_posture.context import AuthDiscovery, MetadataFetch, freeze
    from mcp_posture.net import HttpExchange
    from tests.conftest import make_ctx, run_check
    from tests.fixtures.servers import PRM_URL, secure_prm

    root = PRM_URL.replace("/oauth-protected-resource/mcp", "/oauth-protected-resource")
    headers = (("content-type", "application/json"),)

    def fetch(variant: str, url: str, redirects: tuple[tuple[int, str], ...]) -> MetadataFetch:
        ex = HttpExchange(
            "GET", url, status=200, headers=headers, redirects=redirects, final_url=PRM_URL
        )
        return MetadataFetch(variant, url, ex, freeze(secure_prm()))

    ctx = make_ctx(
        auth=AuthDiscovery(
            prm_fetches=(
                fetch("path-insertion", PRM_URL, ()),
                fetch("root", root, ((302, PRM_URL),)),
            )
        )
    )
    findings = run_check("MCPP-TRN10", ctx)
    assert [f.location for f in findings] == [PRM_URL]


@pytest.mark.check("positive", "MCPP-TRN11")
def test_trn11_endpoint_redirect_is_followed_within_the_origin() -> None:
    """Starlette redirects /mcp to /mcp/ (307); clients follow, so does the scanner."""
    result = run_scan(McpProfile(path="/mcp/", redirect_from="/mcp", require_auth=False))
    (finding,) = by_id(result, "MCPP-TRN11")
    assert finding.severity == Severity.INFO and "/mcp/" in finding.message
    assert result.transport == "streamable-http"  # probed at the final URL
    assert "MCPP-AUTHN01" in ids(result)  # and the open tool surface was found there


@pytest.mark.check("negative", "MCPP-TRN11")
def test_trn11_no_redirect() -> None:
    assert "MCPP-TRN11" not in ids(run_scan(McpProfile()))


def test_trn11_cross_origin_redirect_is_not_followed() -> None:
    from starlette.responses import RedirectResponse as Redirect

    async def elsewhere(request: Request) -> Response:
        return Redirect("https://other.test/mcp", status_code=307)

    app = Starlette(routes=[Route("/mcp", elsewhere, methods=["POST", "GET", "DELETE"])])
    seen: list[str] = []

    async def other(request: Request) -> Response:
        seen.append(request.headers.get("authorization", ""))
        return Response(status_code=500)

    other_app = Starlette(routes=[Route("/mcp", other, methods=["POST", "GET", "DELETE"])])
    from tests.fixtures.servers import MCP_HOST, Router

    result = run_scan(
        transport=lambda: Router({f"https://{MCP_HOST}": app, "https://other.test": other_app}),
        token="secret-token-0123456789",
    )
    (finding,) = by_id(result, "MCPP-TRN11")
    assert finding.severity == Severity.LOW and "not followed" in finding.message
    assert seen == []  # nothing, and certainly no token, was sent to the other origin
