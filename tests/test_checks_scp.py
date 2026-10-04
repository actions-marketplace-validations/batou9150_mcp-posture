from __future__ import annotations

import pytest

from mcp_posture.checks.scp import is_broad
from mcp_posture.models import SpecRevision
from tests.conftest import by_id, ids, run_scan
from tests.fixtures.servers import PRM_URL, AsProfile, McpProfile, secure_as_metadata, secure_prm


@pytest.mark.parametrize("scope", ["*", "admin", "ALL", "files:*", "repo.*", "*.read", "api:admin"])
def test_broad_scopes(scope: str) -> None:
    assert is_broad(scope)


@pytest.mark.parametrize("scope", ["mcp:tools", "notes:read", "openid", "administrative_reports"])
def test_narrow_scopes(scope: str) -> None:
    assert not is_broad(scope)


@pytest.mark.check("positive", "MCPP-SCP01")
def test_scp01_broad_scopes_in_prm_and_challenge() -> None:
    profile = McpProfile(
        prm={**secure_prm(), "scopes_supported": ["mcp:tools", "admin"]},
        challenge=f'Bearer resource_metadata="{PRM_URL}", scope="mcp:* admin"',
    )
    findings = {f.key: f for f in by_id(run_scan(profile), "MCPP-SCP01")}
    assert set(findings) == {"admin", "mcp:*"}
    assert "PRM scopes_supported" in findings["admin"].message
    assert "WWW-Authenticate scope" in findings["admin"].message


@pytest.mark.check("negative", "MCPP-SCP01")
def test_scp01_narrow_scopes() -> None:
    assert "MCPP-SCP01" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-SCP02")
def test_scp02_challenge_without_scope() -> None:
    profile = McpProfile(challenge=f'Bearer resource_metadata="{PRM_URL}"')
    assert by_id(run_scan(profile), "MCPP-SCP02")


@pytest.mark.check("negative", "MCPP-SCP02")
def test_scp02_scope_present_or_older_revision() -> None:
    assert "MCPP-SCP02" not in ids(run_scan(McpProfile()))
    profile = McpProfile(challenge=f'Bearer resource_metadata="{PRM_URL}"')
    assert "MCPP-SCP02" in run_scan(profile, spec=SpecRevision.R2025_06_18).not_applicable


@pytest.mark.check("positive", "MCPP-SCP04")
def test_scp04_scope_unknown_to_as() -> None:
    profile = McpProfile(prm={**secure_prm(), "scopes_supported": ["mcp:tools", "mcp:admin2"]})
    [f] = by_id(run_scan(profile), "MCPP-SCP04")
    assert "mcp:admin2" in f.message


@pytest.mark.check("negative", "MCPP-SCP04")
def test_scp04_consistent_or_as_without_list() -> None:
    assert "MCPP-SCP04" not in ids(run_scan(McpProfile()))
    meta = secure_as_metadata()
    meta.pop("scopes_supported")
    profile = McpProfile(prm={**secure_prm(), "scopes_supported": ["other"]})
    assert "MCPP-SCP04" not in ids(run_scan(profile, AsProfile(metadata=meta)))
