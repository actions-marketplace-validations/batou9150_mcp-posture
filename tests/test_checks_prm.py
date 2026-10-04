from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from mcp_posture.models import Severity, SpecRevision
from tests.conftest import by_id, ids, run_scan
from tests.fixtures.servers import MCP_URL, McpProfile, secure_prm


def prm(**changes: Any) -> dict[str, Any]:
    doc = secure_prm()
    for k, v in changes.items():
        if v is None:
            doc.pop(k, None)
        else:
            doc[k] = v
    return doc


def jws(header: dict[str, Any], claims: dict[str, Any]) -> str:
    def enc(d: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    return f"{enc(header)}.{enc(claims)}.sig"


@pytest.mark.check("positive", "MCPP-PRM01")
def test_prm01_missing() -> None:
    [f] = by_id(run_scan(McpProfile(prm=None)), "MCPP-PRM01")
    assert "tried" in f.evidence[0].summary


@pytest.mark.check("negative", "MCPP-PRM01")
def test_prm01_present_or_not_applicable() -> None:
    assert "MCPP-PRM01" not in ids(run_scan(McpProfile()))
    assert "MCPP-PRM01" not in ids(run_scan(McpProfile(prm=None, require_auth=False)))
    legacy = run_scan(McpProfile(prm=None), spec=SpecRevision.R2025_03_26)
    assert "MCPP-PRM01" in legacy.not_applicable


@pytest.mark.check("positive", "MCPP-PRM02")
def test_prm02_malformed() -> None:
    profile = McpProfile(prm=prm(scopes_supported=[]), prm_content_type="text/plain")
    [f] = by_id(run_scan(profile), "MCPP-PRM02")
    assert "text/plain" in f.message and "scopes_supported" in f.message
    broken = McpProfile(challenge='Bearer resource_metadata="https://mcp.test/nope"')
    assert by_id(run_scan(broken), "MCPP-PRM02")[0].key == "advertised"


@pytest.mark.check("negative", "MCPP-PRM02")
def test_prm02_well_formed() -> None:
    assert "MCPP-PRM02" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-PRM03")
def test_prm03_resource_mismatch() -> None:
    wrong = run_scan(McpProfile(prm=prm(resource="https://evil.test/mcp")))
    assert by_id(wrong, "MCPP-PRM03")[0].severity == Severity.HIGH
    slash = run_scan(McpProfile(prm=prm(resource=MCP_URL + "/")))
    assert by_id(slash, "MCPP-PRM03")[0].severity == Severity.MEDIUM
    missing = run_scan(McpProfile(prm=prm(resource=None)))
    assert "REQUIRED" in by_id(missing, "MCPP-PRM03")[0].message


@pytest.mark.check("negative", "MCPP-PRM03")
def test_prm03_resource_matches() -> None:
    assert "MCPP-PRM03" not in ids(run_scan(McpProfile()))
    root = McpProfile(
        prm=prm(resource="https://mcp.test"),
        prm_variants=frozenset({"root"}),
        challenge='Bearer scope="mcp:tools"',
    )
    assert "MCPP-PRM03" not in ids(run_scan(root))


@pytest.mark.check("positive", "MCPP-PRM04")
def test_prm04_no_authorization_servers() -> None:
    assert by_id(run_scan(McpProfile(prm=prm(authorization_servers=[]))), "MCPP-PRM04")
    assert by_id(run_scan(McpProfile(prm=prm(authorization_servers=None))), "MCPP-PRM04")


@pytest.mark.check("negative", "MCPP-PRM04")
def test_prm04_has_authorization_servers() -> None:
    assert "MCPP-PRM04" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-PRM05")
def test_prm05_http_issuer() -> None:
    profile = McpProfile(prm=prm(authorization_servers=["http://as.example", "http://localhost"]))
    sevs = sorted(f.severity.rank for f in by_id(run_scan(profile), "MCPP-PRM05"))
    assert sevs == [Severity.MEDIUM.rank, Severity.HIGH.rank]


@pytest.mark.check("negative", "MCPP-PRM05")
def test_prm05_https_issuer() -> None:
    assert "MCPP-PRM05" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-PRM06")
def test_prm06_query_bearer() -> None:
    profile = McpProfile(prm=prm(bearer_methods_supported=["header", "query"]))
    assert by_id(run_scan(profile), "MCPP-PRM06")


@pytest.mark.check("negative", "MCPP-PRM06")
def test_prm06_header_only() -> None:
    assert "MCPP-PRM06" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-PRM07")
def test_prm07_no_scopes() -> None:
    assert by_id(run_scan(McpProfile(prm=prm(scopes_supported=None))), "MCPP-PRM07")


@pytest.mark.check("negative", "MCPP-PRM07")
def test_prm07_scopes() -> None:
    assert "MCPP-PRM07" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-PRM08")
def test_prm08_fragment_and_query() -> None:
    frag = run_scan(McpProfile(prm=prm(resource=MCP_URL + "#x")))
    assert by_id(frag, "MCPP-PRM08")[0].severity == Severity.HIGH
    query = run_scan(McpProfile(prm=prm(resource=MCP_URL + "?tenant=1")))
    assert by_id(query, "MCPP-PRM08")[0].severity == Severity.LOW


@pytest.mark.check("negative", "MCPP-PRM08")
def test_prm08_clean_resource() -> None:
    assert "MCPP-PRM08" not in ids(run_scan(McpProfile()))
    assert "MCPP-PRM08" not in ids(run_scan(McpProfile(prm=prm(resource=None))))


@pytest.mark.check("positive", "MCPP-PRM09")
def test_prm09_unsafe_signed_metadata() -> None:
    bad = jws({"alg": "none"}, {"resource": "https://evil.test"})
    [f] = by_id(run_scan(McpProfile(prm=prm(signed_metadata=bad))), "MCPP-PRM09")
    assert "alg=none" in f.message and "no iss" in f.message and "resource" in f.message
    garbage = run_scan(McpProfile(prm=prm(signed_metadata="not-a-jws")))
    assert "decodable" in by_id(garbage, "MCPP-PRM09")[0].message
    not_object = ".".join(
        base64.urlsafe_b64encode(json.dumps(x).encode()).decode() for x in ([1], [2])
    )
    weird = run_scan(McpProfile(prm=prm(signed_metadata=not_object)))
    assert "JSON JWS" in by_id(weird, "MCPP-PRM09")[0].message


@pytest.mark.check("negative", "MCPP-PRM09")
def test_prm09_consistent_signed_metadata() -> None:
    good = jws({"alg": "ES256"}, {"iss": "https://as.test", "resource": MCP_URL})
    assert "MCPP-PRM09" not in ids(run_scan(McpProfile(prm=prm(signed_metadata=good))))
    assert "MCPP-PRM09" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-PRM10")
def test_prm10_offline_access() -> None:
    profile = McpProfile(prm=prm(scopes_supported=["mcp:tools", "offline_access"]))
    assert by_id(run_scan(profile), "MCPP-PRM10")


@pytest.mark.check("negative", "MCPP-PRM10")
def test_prm10_not_applicable_before_2026() -> None:
    profile = McpProfile(prm=prm(scopes_supported=["offline_access"]))
    result = run_scan(profile, spec=SpecRevision.R2025_11_25)
    assert "MCPP-PRM10" in result.not_applicable
    assert "MCPP-PRM10" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-PRM11")
def test_prm11_variants_disagree() -> None:
    profile = McpProfile(
        prm_variants=frozenset({"path-insertion", "root"}),
        prm_overrides={"root": {"authorization_servers": ["https://old-as.test"]}},
    )
    assert by_id(run_scan(profile), "MCPP-PRM11")


@pytest.mark.check("negative", "MCPP-PRM11")
def test_prm11_variants_agree() -> None:
    profile = McpProfile(prm_variants=frozenset({"path-insertion", "root"}))
    assert "MCPP-PRM11" not in ids(run_scan(profile))
