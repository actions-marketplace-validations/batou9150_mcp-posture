from __future__ import annotations

import pytest

from mcp_posture.models import Severity, SpecRevision
from tests.conftest import by_id, ids, run_scan
from tests.fixtures.servers import SAFE_TOOLS, McpProfile


@pytest.mark.check("positive", "MCPP-AUTHN01")
def test_authn01_anonymous_tools_list() -> None:
    result = run_scan(McpProfile(require_auth=False))
    [f] = by_id(result, "MCPP-AUTHN01")
    assert f.severity == Severity.HIGH  # delete_note is destructive
    assert "delete_note" in f.message


@pytest.mark.check("positive", "MCPP-AUTHN01")
def test_authn01_medium_when_harmless_and_oauth_advertised() -> None:
    profile = McpProfile(require_auth=False, tools=[SAFE_TOOLS[0]])
    [f] = by_id(run_scan(profile), "MCPP-AUTHN01")
    assert f.severity == Severity.MEDIUM


@pytest.mark.check("negative", "MCPP-AUTHN01")
def test_authn01_auth_required() -> None:
    assert "MCPP-AUTHN01" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-AUTHN02")
def test_authn02_missing_bearer_challenge() -> None:
    [f] = by_id(run_scan(McpProfile(challenge=None)), "MCPP-AUTHN02")
    assert f.severity == Severity.MEDIUM
    pinned = run_scan(McpProfile(challenge='Basic realm="x"'), spec=SpecRevision.R2025_06_18)
    [f] = by_id(pinned, "MCPP-AUTHN02")
    assert f.severity == Severity.HIGH
    assert "Basic" in f.message
    legacy = run_scan(McpProfile(challenge=None), spec=SpecRevision.R2025_03_26)
    assert by_id(legacy, "MCPP-AUTHN02")[0].severity == Severity.LOW


@pytest.mark.check("negative", "MCPP-AUTHN02")
def test_authn02_bearer_challenge_present() -> None:
    assert "MCPP-AUTHN02" not in ids(run_scan(McpProfile()))
    assert "MCPP-AUTHN02" not in ids(run_scan(McpProfile(require_auth=False)))


@pytest.mark.check("positive", "MCPP-AUTHN03")
def test_authn03_no_prm_discovery() -> None:
    profile = McpProfile(challenge='Bearer realm="mcp"', prm_variants=frozenset())
    [f] = by_id(run_scan(profile), "MCPP-AUTHN03")
    assert "well-known" in f.message
    # 2025-06-18 makes resource_metadata mandatory even when a well-known PRM exists.
    profile = McpProfile(challenge='Bearer realm="mcp"')
    [f] = by_id(run_scan(profile, spec=SpecRevision.R2025_06_18), "MCPP-AUTHN03")
    assert "mandatory" in f.message


@pytest.mark.check("negative", "MCPP-AUTHN03")
def test_authn03_well_known_is_enough_since_2025_11_25() -> None:
    assert "MCPP-AUTHN03" not in ids(run_scan(McpProfile(challenge='Bearer realm="mcp"')))
    assert "MCPP-AUTHN03" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-AUTHN04")
def test_authn04_insecure_or_foreign_prm_url() -> None:
    insecure = McpProfile(challenge='Bearer resource_metadata="http://mcp.test/prm"')
    assert by_id(run_scan(insecure), "MCPP-AUTHN04")[0].severity == Severity.MEDIUM
    foreign = McpProfile(challenge='Bearer resource_metadata="https://other.test/prm"')
    assert by_id(run_scan(foreign), "MCPP-AUTHN04")[0].severity == Severity.INFO


@pytest.mark.check("negative", "MCPP-AUTHN04")
def test_authn04_same_origin_https() -> None:
    assert "MCPP-AUTHN04" not in ids(run_scan(McpProfile()))
    assert "MCPP-AUTHN04" not in ids(run_scan(McpProfile(challenge="Bearer")))


@pytest.mark.check("positive", "MCPP-AUTHN05")
def test_authn05_error_without_credentials() -> None:
    profile = McpProfile(challenge='Bearer error="invalid_token", resource_metadata="x"')
    assert by_id(run_scan(profile), "MCPP-AUTHN05")


@pytest.mark.check("negative", "MCPP-AUTHN05")
def test_authn05_bare_challenge() -> None:
    assert "MCPP-AUTHN05" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-AUTHN06")
def test_authn06_leaky_errors() -> None:
    profile = McpProfile(
        unauth_body='Traceback (most recent call last):\n  File "/usr/src/app/main.py"',
        not_found_body="upstream 10.1.2.3 unreachable",
        headers={"Server": "nginx/1.18.0", "X-Powered-By": "Express"},
    )
    findings = by_id(run_scan(profile), "MCPP-AUTHN06")
    keys = {f.key for f in findings}
    assert {"Python traceback", "private IP address", "banner"} <= keys
    banner = next(f for f in findings if f.key == "banner")
    assert "nginx/1.18.0" in banner.message and "Express" not in banner.message


@pytest.mark.check("negative", "MCPP-AUTHN06")
def test_authn06_generic_errors() -> None:
    assert "MCPP-AUTHN06" not in ids(run_scan(McpProfile(headers={"Server": "nginx"})))
