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
