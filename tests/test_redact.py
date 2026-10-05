from __future__ import annotations

import io
import logging

from hypothesis import given
from hypothesis import strategies as st

from mcp_posture.redact import MASK, RedactingFilter, Redactor


def test_registered_secret_and_json_escaped_form() -> None:
    r = Redactor(['s3cr"et-value'])
    assert r.redact('token s3cr"et-value end') == f"token {MASK} end"
    assert r.redact('{"t": "s3cr\\"et-value"}') == f'{{"t": "{MASK}"}}'


def test_short_secrets_are_ignored() -> None:
    assert Redactor(["ab"]).redact("abc") == "abc"


def test_token_shapes() -> None:
    r = Redactor()
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl"
    assert MASK in r.redact(f"got {jwt}") and jwt not in r.redact(jwt)
    assert r.redact("Authorization: Bearer abc.def-12345") == f"Authorization: Bearer {MASK}"
    assert r.redact("?access_token=abc123&x=1") == f"?access_token={MASK}&x=1"
    assert r.redact('"client_secret": "zzz"') == f'"client_secret": "{MASK}"'
    assert r.redact("401 without a Bearer challenge") == "401 without a Bearer challenge"
    assert r.redact("Bearer abcdefghijklmnopqrstuvwxyz") == f"Bearer {MASK}"


@given(st.text(alphabet=st.characters(min_codepoint=33, max_codepoint=126), min_size=8))
def test_registered_secret_never_survives(secret: str) -> None:
    r = Redactor([secret])
    assert secret not in r.redact(f"prefix {secret} suffix {secret}")


def test_logging_filter() -> None:
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.addFilter(RedactingFilter(Redactor(["topsecret"])))
    log = logging.getLogger("test.redact")
    log.addHandler(handler)
    log.warning("value=%s", "topsecret")
    assert "topsecret" not in buf.getvalue() and MASK in buf.getvalue()


def test_fragments_of_a_secret_are_masked() -> None:
    secret = "tok_" + "A1b2C3d4E5f6G7h8" * 6
    r = Redactor([secret])
    assert "A1b2C3d4E5f6" not in r.redact(f"echo: {secret[:60]}…")  # truncated by a heuristic
    assert r.redact(f"tail {secret[-20:]} end") == f"tail {MASK} end"
    assert r.redact("unrelated text A1b2") == "unrelated text A1b2"  # under the fragment size


def test_wrapped_or_ellipsized_table_cells_do_not_leak() -> None:
    """A server echoing the token: rich wraps/ellipsizes cells before the final text pass."""
    from mcp_posture.models import (
        Confidence,
        Finding,
        Report,
        Severity,
        SpecRevision,
        TargetResult,
        ToolInfo,
    )
    from mcp_posture.report import render

    secret = "s3cr3t-" + "Zq9xW8vU7tS6rR5p" * 9
    finding = Finding(
        check_id="MCPP-AUTHN06",
        title="Error responses leak internals",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        target="https://a.test",
        location="https://a.test",
        message=f"Body echoes {secret} back.",
    )
    report = Report(
        tool=ToolInfo(version="t"),
        generated_at=None,
        mode="passive",
        fail_on=Severity.HIGH,
        targets=(
            TargetResult(
                target="https://a.test",
                reachable=True,
                spec_revision=SpecRevision.R2026_07_28,
                revision_source="default",
                findings=(finding,),
            ),
        ),
    )
    for fmt in ("table", "json", "sarif", "markdown"):
        out = render(report, fmt, Redactor([secret]))
        squeezed = "".join(ch for ch in out if ch.isalnum())
        assert "Zq9xW8vU7tS6" not in squeezed, fmt
