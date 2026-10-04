from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route

from mcp_posture.cimd_lint import LintInput, lint, parse_document, url_problems
from mcp_posture.models import Finding, Severity
from mcp_posture.net import HttpExchange
from tests.test_cli import _free_port, _Server, invoke

URL = "https://app.example.com/oauth/client.json"


def good_doc(**changes: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "client_id": URL,
        "client_name": "Example MCP client",
        "redirect_uris": ["https://app.example.com/callback", "http://127.0.0.1/callback"],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
    }
    for k, v in changes.items():
        if v is None:
            doc.pop(k, None)
        else:
            doc[k] = v
    return doc


def run(doc: dict[str, Any] | None, url: str | None = URL, **kw: Any) -> list[Finding]:
    raw = json.dumps(doc).encode() if doc is not None else b""
    return lint(LintInput(source="t", document=doc, client_id_url=url, raw_size=len(raw), **kw))


def ids(findings: list[Finding]) -> set[str]:
    return {f.check_id for f in findings}


@pytest.mark.check("negative", "MCPP-CIMD50", "MCPP-CIMD51", "MCPP-CIMD52", "MCPP-CIMD53")
@pytest.mark.check("negative", "MCPP-CIMD54", "MCPP-CIMD55", "MCPP-CIMD56", "MCPP-CIMD57")
def test_good_document_is_clean() -> None:
    assert run(good_doc()) == []


@pytest.mark.check("positive", "MCPP-CIMD50")
@pytest.mark.parametrize(
    ("url", "problem"),
    [
        ("http://app.example.com/c.json", "https"),
        ("https://app.example.com", "path"),
        ("https://app.example.com/", "path"),
        ("https://u:p@app.example.com/c.json", "userinfo"),
        ("https://app.example.com/c.json#x", "fragment"),
        ("https://app.example.com/a/../c.json", "'..'"),
        ("https://203.0.113.5/c.json", "IP literal"),
    ],
)
def test_cimd50_bad_client_id_urls(url: str, problem: str) -> None:
    assert any(problem in p for p in url_problems(url))
    findings = [f for f in run(good_doc(client_id=url), url=url) if f.check_id == "MCPP-CIMD50"]
    assert findings and findings[0].severity == Severity.HIGH


def test_cimd50_query_only_is_low() -> None:
    url = URL + "?v=1"
    [f] = [f for f in run(good_doc(client_id=url), url=url) if f.check_id == "MCPP-CIMD50"]
    assert f.severity == Severity.LOW


@pytest.mark.check("positive", "MCPP-CIMD51")
def test_cimd51_client_id_mismatch() -> None:
    assert "MCPP-CIMD51" in ids(run(good_doc(client_id=URL + "/")))
    missing = [f for f in run(good_doc(client_id=None)) if f.check_id == "MCPP-CIMD51"]
    assert missing[0].key == "missing"


@pytest.mark.check("positive", "MCPP-CIMD52")
def test_cimd52_required_fields() -> None:
    keys = {
        f.key
        for f in run(good_doc(client_name=" ", redirect_uris=[]))
        if f.check_id == "MCPP-CIMD52"
    }
    assert keys == {"client_name", "redirect_uris"}
    [f] = run(None, parse_error="invalid JSON")
    assert f.check_id == "MCPP-CIMD52" and f.severity == Severity.HIGH


@pytest.mark.check("positive", "MCPP-CIMD53")
def test_cimd53_redirects() -> None:
    uris = [
        "http://app.example.com/cb",
        "https://*.example.com/cb",
        "https://app.example.com/cb#frag",
        "javascript:alert(1)",
        "relative/cb",
        "com.example.app:/oauth",
        "https:///nohost",
    ]
    findings = [f for f in run(good_doc(redirect_uris=uris)) if f.check_id == "MCPP-CIMD53"]
    flagged = {f.key for f in findings}
    assert flagged == set(uris) - {"com.example.app:/oauth"}
    loopback = run(good_doc(redirect_uris=["http://localhost:3000/cb", "http://[::1]/cb"]))
    [f] = [f for f in loopback if f.check_id == "MCPP-CIMD53"]
    assert f.key == "loopback-only" and f.severity == Severity.INFO


@pytest.mark.check("positive", "MCPP-CIMD54")
def test_cimd54_shared_secrets() -> None:
    doc = good_doc(client_secret="hunter2", token_endpoint_auth_method="client_secret_post")
    findings = {f.key: f.severity for f in run(doc) if f.check_id == "MCPP-CIMD54"}
    assert findings == {"client_secret": Severity.CRITICAL, "method": Severity.HIGH}


@pytest.mark.check("positive", "MCPP-CIMD55")
def test_cimd55_private_keys() -> None:
    jwks = {
        "keys": [
            {"kty": "EC", "kid": "k1", "x": "a", "y": "b", "d": "secret"},
            {"kty": "oct", "k": "s"},
        ]
    }
    doc = good_doc(token_endpoint_auth_method="private_key_jwt", jwks=jwks)
    keys = {f.key for f in run(doc) if f.check_id == "MCPP-CIMD55"}
    assert keys == {"k1", "1"}


@pytest.mark.check("positive", "MCPP-CIMD56")
def test_cimd56_auth_method_coherence() -> None:
    def keys(doc: dict[str, Any]) -> set[str]:
        return {f.key for f in run(doc) if f.check_id == "MCPP-CIMD56"}

    assert keys(good_doc(token_endpoint_auth_method="private_key_jwt")) == {"no-keys"}
    both = good_doc(
        token_endpoint_auth_method="private_key_jwt",
        jwks={"keys": []},
        jwks_uri="http://app.example.com/jwks",
    )
    assert keys(both) == {"both", "jwks_uri"}
    assert keys(good_doc(jwks={"keys": []})) == {"unused-keys"}
    assert keys(good_doc(token_endpoint_auth_method=None)) == {"default"}


@pytest.mark.check("positive", "MCPP-CIMD57")
def test_cimd57_serving() -> None:
    big = good_doc(client_name="x" * 6000)
    assert "MCPP-CIMD57" in ids(run(big))

    def ex(status: int | None, ctype: str = "application/json", **kw: Any) -> HttpExchange:
        return HttpExchange(
            "GET",
            URL,
            status=status,
            headers=(("content-type", ctype), *kw.get("h", ())),
            error=kw.get("error"),
        )

    def keys(exchange: HttpExchange) -> set[str]:
        return {f.key for f in run(good_doc(), exchange=exchange) if f.check_id == "MCPP-CIMD57"}

    assert keys(ex(302, h=(("location", "https://x"),))) == {"redirect"}
    assert keys(ex(404)) == {"status"}
    assert keys(ex(200, "text/plain")) == {"content-type"}
    assert keys(ex(200)) == set()


def test_parse_document() -> None:
    assert parse_document(b"[1]") == (None, "the document is not a JSON object")
    assert parse_document(b"{")[1] is not None
    assert parse_document(b'{"a": 1}') == ({"a": 1}, None)


# --- CLI -----------------------------------------------------------------------------------


def test_cli_lint_file(tmp_path: Path) -> None:
    path = tmp_path / "client.json"
    path.write_text(json.dumps(good_doc(client_secret="hunter2-secret-value")))
    result = invoke("cimd", "lint", str(path), "-f", "json")
    assert result.exit_code == 1
    report = json.loads(result.stdout)
    assert report["mode"] == "lint"
    assert "MCPP-CIMD54" in {f["check_id"] for f in report["targets"][0]["findings"]}
    clean = tmp_path / "ok.json"
    clean.write_text(json.dumps(good_doc()))
    assert invoke("cimd", "lint", str(clean), "--url", URL).exit_code == 0
    mismatch = invoke("cimd", "lint", str(clean), "--url", URL + "x", "-f", "sarif")
    assert mismatch.exit_code == 1 and '"MCPP-CIMD51"' in mismatch.stdout
    assert invoke("cimd", "lint", str(tmp_path / "missing.json")).exit_code == 2
    assert invoke("cimd", "lint", str(clean), "-f", "xml").exit_code == 2
    empty = tmp_path / "empty.json"
    empty.write_text("")
    out = tmp_path / "out.md"
    assert invoke("cimd", "lint", str(empty), "-f", "markdown", "-o", str(out)).exit_code == 1
    assert "MCPP-CIMD52" in out.read_text()


@pytest.fixture
def cimd_server() -> Iterator[str]:
    port = _free_port()
    base = f"http://127.0.0.1:{port}"

    async def doc(request: Request) -> Response:
        return JSONResponse(good_doc(client_id=f"{base}/client.json"))

    async def moved(request: Request) -> Response:
        return RedirectResponse(f"{base}/client.json", status_code=302)

    async def text(request: Request) -> Response:
        return PlainTextResponse(json.dumps(good_doc(client_id=f"{base}/text.json")))

    app = Starlette(
        routes=[Route("/client.json", doc), Route("/moved.json", moved), Route("/text.json", text)]
    )
    server = _Server(app)
    server.port = port
    server.server.config.port = port
    with server:
        yield base


@pytest.mark.network
def test_cli_lint_url(cimd_server: str) -> None:
    def findings(path: str) -> dict[str, set[str]]:
        result = invoke("cimd", "lint", f"{cimd_server}{path}", "--allow-private", "-f", "json")
        out: dict[str, set[str]] = {}
        for f in json.loads(result.stdout)["targets"][0]["findings"]:
            out.setdefault(f["check_id"], set()).add(f["key"])
        return out

    ok = findings("/client.json")
    assert set(ok) == {"MCPP-CIMD50"}  # loopback http only fails the https rule
    assert findings("/moved.json")["MCPP-CIMD57"] == {"redirect"}
    assert findings("/text.json")["MCPP-CIMD57"] == {"content-type"}
    blocked = invoke("cimd", "lint", f"{cimd_server}/client.json")
    assert blocked.exit_code == 3
