from __future__ import annotations

from typing import Any

import pytest

from mcp_posture.models import Severity, SpecRevision
from tests.conftest import by_id, ids, run_scan
from tests.fixtures.servers import ISSUER, AsProfile, McpProfile, secure_as_metadata, secure_prm


def meta(**changes: Any) -> dict[str, Any]:
    doc = secure_as_metadata()
    for k, v in changes.items():
        if v is None:
            doc.pop(k, None)
        else:
            doc[k] = v
    return doc


def scan_as(**changes: Any) -> Any:
    return run_scan(McpProfile(), AsProfile(metadata=meta(**changes)))


@pytest.mark.check("positive", "MCPP-ASM01")
def test_asm01_missing_metadata() -> None:
    [f] = by_id(run_scan(McpProfile(), AsProfile(metadata=None)), "MCPP-ASM01")
    assert "oauth-authorization-server" in (f.evidence[0].excerpt or "")


@pytest.mark.check("negative", "MCPP-ASM01")
def test_asm01_found_via_any_variant() -> None:
    for variant in ("rfc8414", "oidc-insert"):
        assert "MCPP-ASM01" not in ids(run_scan(McpProfile(), AsProfile(variant=variant)))
    tenant = f"{ISSUER}/tenant1"
    prm = {**secure_prm(), "authorization_servers": [tenant]}
    auth = AsProfile(issuer=tenant, metadata=secure_as_metadata(tenant), variant="oidc-append")
    result = run_scan(McpProfile(prm=prm), auth)
    assert "MCPP-ASM01" not in ids(result)
    assert "MCPP-ASM02" not in ids(result)


@pytest.mark.check("positive", "MCPP-ASM02")
def test_asm02_issuer_mismatch() -> None:
    [f] = by_id(scan_as(issuer="https://evil.test"), "MCPP-ASM02")
    assert "evil.test" in f.message
    assert by_id(scan_as(issuer=None), "MCPP-ASM02")
    shape = {f.key for f in by_id(scan_as(issuer=ISSUER + "?x=1"), "MCPP-ASM02")}
    assert shape == {"shape", ""}


@pytest.mark.check("negative", "MCPP-ASM02")
def test_asm02_issuer_matches() -> None:
    assert "MCPP-ASM02" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-ASM03")
def test_asm03_http_endpoints() -> None:
    findings = by_id(
        scan_as(token_endpoint="http://as.test/token", jwks_uri="http://localhost/jwks"),
        "MCPP-ASM03",
    )
    assert {(f.key, f.severity) for f in findings} == {
        ("token_endpoint", Severity.HIGH),
        ("jwks_uri", Severity.MEDIUM),
    }


@pytest.mark.check("negative", "MCPP-ASM03")
def test_asm03_https_endpoints() -> None:
    assert "MCPP-ASM03" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-ASM04")
def test_asm04_no_s256() -> None:
    [f] = by_id(scan_as(code_challenge_methods_supported=None), "MCPP-ASM04")
    assert f.severity == Severity.CRITICAL and "absent" in f.message
    [f] = by_id(scan_as(code_challenge_methods_supported=["plain"]), "MCPP-ASM04")
    assert "does not include S256" in f.message


@pytest.mark.check("negative", "MCPP-ASM04")
def test_asm04_s256() -> None:
    assert "MCPP-ASM04" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-ASM05")
def test_asm05_plain() -> None:
    result = scan_as(code_challenge_methods_supported=["S256", "plain"])
    assert by_id(result, "MCPP-ASM05")[0].severity == Severity.HIGH
    assert "MCPP-ASM04" not in ids(result)


@pytest.mark.check("negative", "MCPP-ASM05")
def test_asm05_s256_only() -> None:
    assert "MCPP-ASM05" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-ASM06")
def test_asm06_deprecated_grants() -> None:
    [f] = by_id(scan_as(grant_types_supported=["authorization_code", "password"]), "MCPP-ASM06")
    assert f.severity == Severity.HIGH and "password" in f.message
    [f] = by_id(scan_as(grant_types_supported=None), "MCPP-ASM06")
    assert f.severity == Severity.LOW and f.key == "default"


@pytest.mark.check("negative", "MCPP-ASM06")
def test_asm06_modern_grants() -> None:
    assert "MCPP-ASM06" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-ASM07")
def test_asm07_response_types() -> None:
    keys = {f.key for f in by_id(scan_as(response_types_supported=["token"]), "MCPP-ASM07")}
    assert keys == {"code", "token"}
    hybrid = scan_as(response_types_supported=["code", "code id_token token"])
    assert {f.key for f in by_id(hybrid, "MCPP-ASM07")} == {"token"}


@pytest.mark.check("negative", "MCPP-ASM07")
def test_asm07_code_only() -> None:
    assert "MCPP-ASM07" not in ids(scan_as(response_types_supported=["code", "code id_token"]))


@pytest.mark.check("positive", "MCPP-ASM08")
def test_asm08_passive_note() -> None:
    assert by_id(run_scan(McpProfile()), "MCPP-ASM08")[0].severity == Severity.INFO


@pytest.mark.check("negative", "MCPP-ASM08")
def test_asm08_not_without_authorization_server() -> None:
    assert "MCPP-ASM08" not in ids(run_scan(McpProfile(), AsProfile(metadata=None)))


@pytest.mark.check("positive", "MCPP-ASM09")
def test_asm09_dcr_exposed() -> None:
    assert by_id(scan_as(registration_endpoint=f"{ISSUER}/register"), "MCPP-ASM09")


@pytest.mark.check("negative", "MCPP-ASM09")
def test_asm09_no_dcr() -> None:
    assert "MCPP-ASM09" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-ASM10")
def test_asm10_dcr_without_cimd() -> None:
    changes = {
        "registration_endpoint": f"{ISSUER}/register",
        "client_id_metadata_document_supported": None,
    }
    assert by_id(scan_as(**changes), "MCPP-ASM10")[0].severity == Severity.MEDIUM
    older = run_scan(
        McpProfile(), AsProfile(metadata=meta(**changes)), spec=SpecRevision.R2025_11_25
    )
    assert by_id(older, "MCPP-ASM10")[0].severity == Severity.LOW


@pytest.mark.check("negative", "MCPP-ASM10")
def test_asm10_dcr_with_cimd_or_old_revision() -> None:
    assert "MCPP-ASM10" not in ids(scan_as(registration_endpoint=f"{ISSUER}/register"))
    changes = {"registration_endpoint": f"{ISSUER}/register"}
    old = run_scan(
        McpProfile(),
        AsProfile(metadata=meta(client_id_metadata_document_supported=None, **changes)),
        spec=SpecRevision.R2025_06_18,
    )
    assert "MCPP-ASM10" in old.not_applicable


@pytest.mark.check("positive", "MCPP-ASM11")
def test_asm11_no_iss_parameter() -> None:
    finding = by_id(scan_as(authorization_response_iss_parameter_supported=None), "MCPP-ASM11")
    assert finding[0].severity == Severity.LOW


@pytest.mark.check("positive", "MCPP-ASM11")
def test_asm11_mix_up_with_two_authorization_servers() -> None:
    other = "https://as2.test"
    prm = {**secure_prm(), "authorization_servers": [ISSUER, other]}
    from tests.fixtures.servers import Router, as_app, mcp_app

    def transport() -> Router:
        return Router(
            {
                "https://mcp.test": mcp_app(McpProfile(prm=prm)),
                "https://as.test": as_app(
                    AsProfile(metadata=meta(authorization_response_iss_parameter_supported=None))
                ),
                "https://as2.test": as_app(
                    AsProfile(
                        issuer=other,
                        metadata={
                            **secure_as_metadata(other),
                            "authorization_response_iss_parameter_supported": False,
                        },
                    )
                ),
            }
        )

    findings = by_id(run_scan(transport=transport), "MCPP-ASM11")
    assert len(findings) == 2
    assert all(f.severity == Severity.MEDIUM for f in findings)


@pytest.mark.check("negative", "MCPP-ASM11")
def test_asm11_iss_supported() -> None:
    assert "MCPP-ASM11" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-ASM12")
def test_asm12_alg_none() -> None:
    result = scan_as(token_endpoint_auth_signing_alg_values_supported=["RS256", "none"])
    assert by_id(result, "MCPP-ASM12")


@pytest.mark.check("negative", "MCPP-ASM12")
def test_asm12_signed_algs_only() -> None:
    assert "MCPP-ASM12" not in ids(run_scan(McpProfile()))


@pytest.mark.check("positive", "MCPP-ASM13")
def test_asm13_legacy_defaults_without_metadata() -> None:
    profile = McpProfile(revision="2025-03-26", prm=None, authorization_server_paths=True)
    result = run_scan(profile, spec=SpecRevision.R2025_03_26)
    [f] = by_id(result, "MCPP-ASM13")
    assert "3 default endpoint(s)" in f.message


@pytest.mark.check("negative", "MCPP-ASM13")
def test_asm13_legacy_with_metadata() -> None:
    origin = "https://mcp.test"
    profile = McpProfile(
        revision="2025-03-26", prm=None, legacy_as_metadata=secure_as_metadata(origin)
    )
    result = run_scan(profile, spec=SpecRevision.R2025_03_26)
    assert "MCPP-ASM13" not in ids(result)
    assert "MCPP-ASM02" not in ids(result)
    assert "MCPP-ASM13" in run_scan(McpProfile()).not_applicable
