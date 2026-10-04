from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from mcp_posture.discovery import (
    as_metadata_candidates,
    bearer_challenge,
    parse_www_authenticate,
    prm_candidates,
    well_known_append,
    well_known_insert,
)


def test_parse_bearer_with_params() -> None:
    [c] = parse_www_authenticate(
        ['Bearer realm="mcp", resource_metadata="https://h/.well-known/x", scope="a b"']
    )
    assert c.scheme == "Bearer"
    assert c.get("resource_metadata") == "https://h/.well-known/x"
    assert c.get("scope") == "a b"
    assert c.get("REALM") == "mcp"


def test_parse_multiple_challenges_in_one_header() -> None:
    challenges = parse_www_authenticate(['Bearer error="invalid_token", DPoP algs="ES256 PS256"'])
    assert [c.scheme for c in challenges] == ["Bearer", "DPoP"]
    assert challenges[1].get("algs") == "ES256 PS256"


def test_parse_multiple_header_values_and_token_params() -> None:
    challenges = parse_www_authenticate(["Basic realm=simple", "Bearer scope=read"])
    assert [c.get("realm") for c in challenges] == ["simple", None]
    bearer = bearer_challenge(challenges)
    assert bearer is not None and bearer.get("scope") == "read"


def test_parse_token68_and_escapes() -> None:
    [c] = parse_www_authenticate(["Negotiate abc123=="])
    assert c.token68 == "abc123=="
    [c] = parse_www_authenticate(['Bearer realm="a \\"quoted\\" realm"'])
    assert c.get("realm") == 'a "quoted" realm'


def test_parse_bare_scheme_and_garbage() -> None:
    [c] = parse_www_authenticate(["Bearer"])
    assert c.scheme == "Bearer" and dict(c.params) == {}
    assert parse_www_authenticate([""]) == ()
    assert parse_www_authenticate(['=== ,,, "']) == ()
    [c] = parse_www_authenticate(['Bearer realm="unterminated'])
    assert c.get("realm") == "unterminated"


def test_duplicate_params_keep_first() -> None:
    [c] = parse_www_authenticate(['Bearer scope="a", scope="b"'])
    assert c.get("scope") == "a"


_token = st.text(alphabet="abcdefghijklmnopqrstuvwxyzABCDEF0123456789-_", min_size=1, max_size=12)
_value = st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E), max_size=30)


@given(scheme=_token, params=st.dictionaries(_token, _value, max_size=5))
def test_roundtrip_generated_challenges(scheme: str, params: dict[str, str]) -> None:
    def quote(v: str) -> str:
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'

    header = scheme + " " + ", ".join(f"{k}={quote(v)}" for k, v in params.items())
    [c] = parse_www_authenticate([header.strip()])
    assert c.scheme == scheme
    expected: dict[str, str] = {}
    for k, v in params.items():
        expected.setdefault(k.lower(), v)
    assert dict(c.params) == expected


@given(st.text(max_size=200))
def test_parser_never_raises(text: str) -> None:
    for c in parse_www_authenticate([text]):
        assert c.scheme


def test_well_known_urls() -> None:
    assert (
        well_known_insert("https://h/public/mcp", "/.well-known/oauth-protected-resource")
        == "https://h/.well-known/oauth-protected-resource/public/mcp"
    )
    assert well_known_insert("https://h/", "/.well-known/x") == "https://h/.well-known/x"
    assert well_known_append("https://h/t1/", "/.well-known/openid-configuration") == (
        "https://h/t1/.well-known/openid-configuration"
    )


def test_prm_candidates_order_and_dedupe() -> None:
    assert prm_candidates(
        "https://h/mcp", "https://h/.well-known/oauth-protected-resource/mcp"
    ) == [
        ("www-authenticate", "https://h/.well-known/oauth-protected-resource/mcp"),
        ("root", "https://h/.well-known/oauth-protected-resource"),
    ]
    assert [v for v, _ in prm_candidates("https://h/", None)] == ["path-insertion"]


def test_as_metadata_candidates() -> None:
    assert [u for _, u in as_metadata_candidates("https://as/tenant1")] == [
        "https://as/.well-known/oauth-authorization-server/tenant1",
        "https://as/.well-known/openid-configuration/tenant1",
        "https://as/tenant1/.well-known/openid-configuration",
    ]
    assert len(as_metadata_candidates("https://as")) == 2
