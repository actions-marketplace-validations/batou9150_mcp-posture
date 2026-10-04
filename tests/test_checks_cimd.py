from __future__ import annotations

import pytest

from mcp_posture.checks.cimd import registration_strategies
from mcp_posture.models import SpecRevision
from tests.conftest import by_id, ids, run_scan
from tests.fixtures.servers import ISSUER, AsProfile, McpProfile, secure_as_metadata


def _no_cimd() -> AsProfile:
    doc = secure_as_metadata()
    doc.pop("client_id_metadata_document_supported")
    doc["registration_endpoint"] = f"{ISSUER}/register"
    return AsProfile(metadata=doc)


@pytest.mark.check("positive", "MCPP-CIMD01")
def test_cimd01_not_advertised() -> None:
    assert by_id(run_scan(McpProfile(), _no_cimd()), "MCPP-CIMD01")


@pytest.mark.check("negative", "MCPP-CIMD01")
def test_cimd01_advertised_or_old_revision() -> None:
    assert "MCPP-CIMD01" not in ids(run_scan(McpProfile()))
    old = run_scan(McpProfile(), _no_cimd(), spec=SpecRevision.R2025_06_18)
    assert "MCPP-CIMD01" in old.not_applicable


@pytest.mark.check("positive", "MCPP-CIMD02")
def test_cimd02_strategy_summary() -> None:
    [f] = by_id(run_scan(McpProfile(), _no_cimd()), "MCPP-CIMD02")
    assert f.message == "Registration paths offered: DCR, pre-registration."


@pytest.mark.check("negative", "MCPP-CIMD02")
def test_cimd02_no_authorization_server() -> None:
    assert "MCPP-CIMD02" not in ids(run_scan(McpProfile(require_auth=False, prm=None)))
    assert registration_strategies(None) == []
