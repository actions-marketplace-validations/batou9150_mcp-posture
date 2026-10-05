"""`mcp-posture login`: the OAuth flow against in-process fixtures, the test playing the browser.

The authorization server is the fixture in tests/fixtures/servers.py (auto-consent); the
redirect lands on the real loopback listener. Nothing leaves the machine.
"""

from __future__ import annotations

import asyncio
import os
import re
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
from typer.testing import CliRunner

from mcp_posture import cli
from mcp_posture.login import (
    CallbackServer,
    LoginError,
    LoginNotRequired,
    LoginOptions,
    LoginResult,
    LoginUI,
    login,
)
from mcp_posture.redact import MASK, Redactor
from tests.conftest import FAST_NET
from tests.fixtures.servers import (
    GOOD_TOKEN,
    ISSUER,
    MCP_URL,
    PRE_CLIENT,
    PRM_URL,
    AsProfile,
    McpProfile,
    Router,
    router,
    secure_as_metadata,
    secure_prm,
)

CIMD_URL = "https://client.test/mcp-posture.json"
DCR_METADATA = {**secure_as_metadata(), "registration_endpoint": f"{ISSUER}/register"}


def cimd_app(document: dict[str, Any]) -> Starlette:
    async def doc(request: Request) -> Response:
        import json

        return Response(json.dumps(document), media_type="application/json")

    return Starlette(routes=[Route("/mcp-posture.json", doc)])


def good_cimd() -> dict[str, Any]:
    return {
        "client_id": CIMD_URL,
        "client_name": "mcp-posture (test)",
        "client_uri": "https://client.test/",
        "redirect_uris": ["http://127.0.0.1/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }


class Flow:
    """One login run: router, captured messages, the redactor, and the browser stand-in."""

    def __init__(
        self,
        mcp: McpProfile | None = None,
        auth: AsProfile | None = None,
        extra: dict[str, Any] | None = None,
        confirm: Any = None,
        browser: bool = True,
    ) -> None:
        self.auth = auth or AsProfile()
        self.router: Router = router(mcp, self.auth, extra=extra)()
        self.messages: list[str] = []
        self.redactor = Redactor()
        self.opened: list[str] = []
        self.ui = LoginUI(
            say=self.messages.append,
            open_url=self._browse if browser else (lambda url: False),
            confirm=confirm,
        )

    async def _browse(self, url: str) -> None:
        self.opened.append(url)
        async with httpx.AsyncClient(transport=self.router) as c:
            resp = await c.get(url)
        location = resp.headers.get("location")
        if location:  # the AS consented: follow the redirect to the real loopback listener
            async with httpx.AsyncClient(trust_env=False) as c:
                await c.get(location)

    def run(self, opts: LoginOptions | None = None, url: str = MCP_URL) -> LoginResult:
        opts = opts or LoginOptions(client_id=PRE_CLIENT)
        opts = replace(opts, timeout=min(opts.timeout, 5.0))
        return asyncio.run(
            login(
                url,
                opts,
                FAST_NET,
                self.ui,
                redactor=self.redactor,
                transport_factory=lambda: self.router,
            )
        )

    def seen(self, kind: str) -> list[Any]:
        return [v for k, v in self.auth.log if k == kind]


def test_pre_registered_client_happy_path() -> None:
    flow = Flow()
    result = flow.run()
    assert result.access_token == GOOD_TOKEN and result.strategy == "pre-registered"
    assert result.scope == "mcp:tools"  # from the 401 challenge
    (authz,) = flow.seen("authorize")
    assert authz["code_challenge_method"] == "S256" and authz["resource"] == MCP_URL
    assert authz["redirect_uri"].startswith("http://127.0.0.1:")
    (token_req,) = flow.seen("token")
    assert token_req["resource"] == MCP_URL and "client_secret" not in token_req
    # Every secret of the flow is registered with the redactor.
    for secret in (GOOD_TOKEN, token_req["code"], token_req["code_verifier"]):
        assert flow.redactor.redact(secret) == MASK
    assert "refresh-token-never-stored-0123" not in repr(result)
    # The URL is always shown: the browser may open in the wrong profile.
    shown = next(m for m in flow.messages if m.startswith("Opened your browser"))
    assert flow.opened[0] in shown
    assert GOOD_TOKEN not in repr(result)


def test_dcr_with_consent_registers_then_deletes_the_client() -> None:
    flow = Flow(auth=AsProfile(metadata=DCR_METADATA))
    result = flow.run(LoginOptions(register=True))
    assert result.strategy == "dcr" and result.client_id == "dcr-1"
    (registration,) = flow.seen("register")
    assert registration["token_endpoint_auth_method"] == "none"
    # The AS advertises refresh_token; some servers refuse a registration without it.
    assert registration["grant_types"] == ["authorization_code", "refresh_token"]
    assert registration["redirect_uris"][0].startswith("http://127.0.0.1:")
    assert flow.seen("unregister") == ["dcr-1"]
    assert any("Deleted the temporary client" in m for m in flow.messages)


def test_dcr_keep_client() -> None:
    flow = Flow(auth=AsProfile(metadata=DCR_METADATA))
    flow.run(LoginOptions(register=True, keep_client=True))
    assert flow.seen("unregister") == []
    assert any("--client-id dcr-1" in m for m in flow.messages)


def test_dcr_without_management_endpoint_says_so() -> None:
    flow = Flow(auth=AsProfile(metadata=DCR_METADATA, dcr_management=False))
    flow.run(LoginOptions(register=True))
    assert any("stays on the authorization server" in m for m in flow.messages)


def test_dcr_needs_consent() -> None:
    with pytest.raises(LoginError, match="--register"):
        Flow(auth=AsProfile(metadata=DCR_METADATA)).run(LoginOptions())
    asked: list[str] = []

    def refuse(question: str) -> bool:
        asked.append(question)
        return False

    with pytest.raises(LoginError, match="--register"):
        Flow(auth=AsProfile(metadata=DCR_METADATA), confirm=refuse).run(LoginOptions())
    assert asked == ["Register a new client on as.test?"]
    flow = Flow(auth=AsProfile(metadata=DCR_METADATA), confirm=lambda q: True)
    assert flow.run(LoginOptions()).strategy == "dcr"


def test_dcr_confidential_client_uses_basic_auth_and_redacts_the_secret() -> None:
    flow = Flow(auth=AsProfile(metadata=DCR_METADATA, dcr_secret=True))
    flow.run(LoginOptions(register=True))
    (token_req,) = flow.seen("token")
    assert "client_secret" not in token_req  # sent in the Authorization header instead
    assert flow.redactor.redact("dcr-secret-0123456789") == MASK


def test_cimd_client() -> None:
    flow = Flow(extra={"https://client.test": cimd_app(good_cimd())})
    result = flow.run(LoginOptions(client_metadata_url=CIMD_URL))
    assert result.strategy == "cimd" and result.client_id == CIMD_URL
    assert flow.seen("authorize")[0]["client_id"] == CIMD_URL


def test_cimd_document_problems_are_refused() -> None:
    no_loopback = {**good_cimd(), "redirect_uris": ["https://client.test/cb"]}
    with pytest.raises(LoginError, match="redirect_uris"):
        Flow(extra={"https://client.test": cimd_app(no_loopback)}).run(
            LoginOptions(client_metadata_url=CIMD_URL)
        )
    leaky = {**good_cimd(), "client_secret": "s3cr3t"}
    with pytest.raises(LoginError, match="blocking problems"):
        Flow(extra={"https://client.test": cimd_app(leaky)}).run(
            LoginOptions(client_metadata_url=CIMD_URL)
        )
    no_cimd = {k: v for k, v in secure_as_metadata().items() if "client_id_metadata" not in k}
    with pytest.raises(LoginError, match="does not advertise Client ID Metadata"):
        Flow(auth=AsProfile(metadata=no_cimd)).run(LoginOptions(client_metadata_url=CIMD_URL))


def test_no_client_identity() -> None:
    with pytest.raises(LoginError, match="no way to obtain a client_id"):
        Flow().run(LoginOptions(default_client=False))
    # The default client document is unreachable here and there is no DCR to fall back on.
    with pytest.raises(LoginError, match="cannot fetch the client metadata document"):
        Flow().run(LoginOptions())


@pytest.mark.parametrize(
    ("mcp", "auth", "message"),
    [
        (McpProfile(prm={**secure_prm(), "resource": "https://other.test/mcp"}), None, "resource"),
        (None, AsProfile(metadata=secure_as_metadata(issuer="https://evil.test")), "issuer"),
        (
            None,
            AsProfile(metadata={**secure_as_metadata(), "code_challenge_methods_supported": []}),
            "S256",
        ),
        (
            None,
            AsProfile(
                metadata={
                    k: v
                    for k, v in secure_as_metadata().items()
                    if k != "code_challenge_methods_supported"
                }
            ),
            "S256",
        ),
        (
            None,
            AsProfile(metadata={**secure_as_metadata(), "token_endpoint": "http://as.test/token"}),
            "not an https URL",
        ),
    ],
)
def test_discovery_refusals(mcp: McpProfile | None, auth: AsProfile | None, message: str) -> None:
    with pytest.raises(LoginError, match=message):
        Flow(mcp, auth).run()


def test_choose_among_several_authorization_servers() -> None:
    prm = {**secure_prm(), "authorization_servers": ["https://other-as.test", ISSUER]}
    flow = Flow(McpProfile(prm=prm))
    assert (
        flow.run(LoginOptions(client_id=PRE_CLIENT, authorization_server=ISSUER)).issuer == ISSUER
    )
    with pytest.raises(LoginError, match="must be one of"):
        Flow(McpProfile(prm=prm)).run(
            LoginOptions(client_id=PRE_CLIENT, authorization_server="https://nope.test")
        )


@pytest.mark.parametrize("mode", ["missing", "wrong"])
def test_iss_is_validated(mode: str) -> None:
    with pytest.raises(LoginError, match="RFC 9207"):
        Flow(auth=AsProfile(iss_mode=mode)).run()


def test_user_denial_is_reported_without_echoing_markup() -> None:
    with pytest.raises(LoginError, match="access_denied: The user said no"):
        Flow(auth=AsProfile(deny=True)).run()


def test_non_bearer_token_type_is_refused() -> None:
    with pytest.raises(LoginError, match="Bearer only"):
        Flow(auth=AsProfile(token_type="DPoP")).run()


def test_jwt_audience_mismatch_is_a_warning() -> None:
    result = Flow(auth=AsProfile(jwt_aud="https://somewhere-else.test")).run()
    assert any("audience binding is in doubt" in w for w in result.warnings)
    ok = Flow(auth=AsProfile(jwt_aud=MCP_URL)).run()
    assert ok.warnings == ()


def test_server_without_auth() -> None:
    with pytest.raises(LoginNotRequired):
        Flow(McpProfile(require_auth=False)).run()


def test_unreachable_server() -> None:
    with pytest.raises(LoginError) as e:
        Flow().run(url="https://nowhere.test/mcp")
    assert e.value.unreachable


def test_no_browser_prints_the_url_and_times_out() -> None:
    flow = Flow(browser=False)
    with pytest.raises(LoginError, match="no authorization response"):
        flow.run(LoginOptions(client_id=PRE_CLIENT, timeout=0.3))
    printed = next(m for m in flow.messages if m.startswith("Open this URL"))
    assert "https://as.test/authorize?" in printed and "code_challenge_method=S256" in printed


def test_legacy_2025_03_26_server_is_its_own_authorization_server() -> None:
    legacy = {
        **secure_as_metadata(issuer="https://mcp.test"),
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "authorization_response_iss_parameter_supported": False,
    }
    mcp = McpProfile(revision="2025-03-26", prm=None, challenge="Bearer", legacy_as_metadata=legacy)
    result = Flow(mcp, AsProfile(iss_mode="missing")).run()
    assert result.issuer == "https://mcp.test" and result.resource == MCP_URL


# --- the loopback listener ------------------------------------------------------------------


def test_callback_server_accepts_only_the_expected_state() -> None:
    async def go() -> tuple[dict[str, str], list[httpx.Response]]:
        server = CallbackServer("expected-state")
        await server.start()
        base = server.redirect_uri
        responses = []
        async with httpx.AsyncClient(trust_env=False) as c:
            responses.append(await c.get(f"{base}?state=forged&code=x"))
            non_ascii = await c.get(f"{base}?state=%C3%A9t%C3%A9&code=x")
            assert non_ascii.status_code == 400
            responses.append(await c.get(f"{base}?state=expected-state&state=again&code=x"))
            responses.append(await c.post(base))
            responses.append(await c.get(base.replace("/callback", "/other")))
            responses.append(
                await c.get(f"{base}?state=expected-state&code=c0de&x=<script>alert(1)</script>")
            )
            responses.append(await c.get(f"{base}?state=expected-state&code=second"))
        params = await server.wait(1)
        await server.close()
        return params, responses

    params, (forged, repeated, post, other, ok, second) = asyncio.run(go())
    assert params["code"] == "c0de"
    assert (forged.status_code, repeated.status_code, post.status_code) == (400, 400, 405)
    assert (other.status_code, ok.status_code, second.status_code) == (404, 200, 404)
    assert "script" not in ok.text and "c0de" not in ok.text  # nothing is echoed
    assert ok.headers["content-security-policy"].startswith("default-src 'none'")
    assert ok.headers["cache-control"] == "no-store"
    assert server_is_loopback_only(ok)


def server_is_loopback_only(response: httpx.Response) -> bool:
    return response.url.host == "127.0.0.1"


# --- CLI ------------------------------------------------------------------------------------

runner = CliRunner()


def fake_result(**overrides: Any) -> LoginResult:
    base: dict[str, Any] = {
        "access_token": "cli-token-0123456789abcdef",
        "token_type": "Bearer",
        "scope": "mcp:tools",
        "expires_in": 3600,
        "client_id": PRE_CLIENT,
        "strategy": "pre-registered",
        "issuer": ISSUER,
        "resource": MCP_URL,
        "warnings": (),
    }
    return LoginResult(**{**base, **overrides})


@pytest.fixture
def fake_login(monkeypatch: pytest.MonkeyPatch) -> list[LoginOptions]:
    calls: list[LoginOptions] = []

    def run(url: str, opts: LoginOptions, net: Any, redactor: Redactor) -> LoginResult:
        calls.append(opts)
        redactor.add("cli-token-0123456789abcdef")
        return fake_result()

    monkeypatch.setattr(cli, "run_login", run)
    return calls


def test_cli_login_prints_the_token_only_when_captured(
    fake_login: list[LoginOptions], monkeypatch: pytest.MonkeyPatch
) -> None:
    result = runner.invoke(cli.app, ["login", MCP_URL, "--client-id", "abc", "--scope", "a b"])
    assert result.exit_code == 0
    assert result.stdout == "cli-token-0123456789abcdef\n"
    assert fake_login[0].client_id == "abc" and fake_login[0].scope == "a b"
    monkeypatch.setattr(cli, "_stdout_is_tty", lambda: True)
    refused = runner.invoke(cli.app, ["login", MCP_URL])
    assert refused.exit_code == 2 and "refusing to print a token" in refused.stderr
    assert len(fake_login) == 1  # refused before logging in
    shown = runner.invoke(cli.app, ["login", MCP_URL, "--show-token"])
    assert shown.exit_code == 0 and "cli-token" in shown.stdout


def test_cli_token_file(fake_login: list[LoginOptions], tmp_path: Path) -> None:
    path = tmp_path / "token"
    result = runner.invoke(cli.app, ["login", MCP_URL, "--token-file", str(path)])
    assert result.exit_code == 0 and result.stdout == ""
    assert path.read_text() == "cli-token-0123456789abcdef\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    again = runner.invoke(cli.app, ["login", MCP_URL, "--token-file", str(path)])
    assert again.exit_code == 0  # an existing 0600 file of ours is replaced atomically
    path.chmod(0o644)
    loose = runner.invoke(cli.app, ["login", MCP_URL, "--token-file", str(path)])
    assert loose.exit_code == 2 and "must be 600" in loose.stderr
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "elsewhere")
    sym = runner.invoke(cli.app, ["login", MCP_URL, "--token-file", str(link)])
    assert sym.exit_code == 2 and not (tmp_path / "elsewhere").exists()


def test_cli_login_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    def failing(*args: Any) -> LoginResult:
        raise LoginError("authorization failed: [bold]access_denied[/bold]")

    monkeypatch.setattr(cli, "run_login", failing)
    result = runner.invoke(cli.app, ["login", MCP_URL])
    assert result.exit_code == 1 and "[bold]access_denied[/bold]" in result.stderr
    scan = runner.invoke(cli.app, ["scan", MCP_URL, "--login", "--no-tls-probe"])
    assert scan.exit_code == cli.EXIT_LOGIN_FAILED

    def unreachable(*args: Any) -> LoginResult:
        raise LoginError("cannot reach", unreachable=True)

    monkeypatch.setattr(cli, "run_login", unreachable)
    assert runner.invoke(cli.app, ["login", MCP_URL]).exit_code == 3

    def not_required(*args: Any) -> LoginResult:
        raise LoginNotRequired

    monkeypatch.setattr(cli, "run_login", not_required)
    ok = runner.invoke(cli.app, ["login", MCP_URL])
    assert ok.exit_code == 0 and "does not require authentication" in ok.stderr


def test_cli_scan_login_usage(
    fake_login: list[LoginOptions], monkeypatch: pytest.MonkeyPatch
) -> None:
    two = runner.invoke(cli.app, ["scan", MCP_URL, "https://b.test/mcp", "--login"])
    assert two.exit_code == 2 and "exactly one target" in two.stderr
    monkeypatch.setenv("TOK", "x" * 20)
    both = runner.invoke(cli.app, ["scan", MCP_URL, "--login", "--token-env", "TOK"])
    assert both.exit_code == 2 and "exclusive" in both.stderr
    missing = runner.invoke(cli.app, ["scan", MCP_URL, "--login", "--client-secret-env", "NOPE"])
    assert missing.exit_code == 2 and "NOPE" in missing.stderr
    assert fake_login == []


def test_cli_login_reads_the_config_table(fake_login: list[LoginOptions], tmp_path: Path) -> None:
    cfg = tmp_path / "mcp-posture.toml"
    cfg.write_text(
        '[login]\nclient_id = "from-config"\nregister = true\nport = 8765\n', encoding="utf-8"
    )
    runner.invoke(cli.app, ["login", MCP_URL, "--config", str(cfg)])
    runner.invoke(cli.app, ["login", MCP_URL, "--config", str(cfg), "--client-id", "cli"])
    first, second = fake_login
    assert (first.client_id, first.register, first.port) == ("from-config", True, 8765)
    assert second.client_id == "cli"
    bad = tmp_path / "bad.toml"
    bad.write_text('[login]\nclient_secret = "no"\n', encoding="utf-8")
    assert runner.invoke(cli.app, ["login", MCP_URL, "--config", str(bad)]).exit_code == 2


def test_scan_login_end_to_end_lists_the_tool_surface() -> None:
    """Log in, then scan with the token in memory: the tools behind auth are listed."""
    from mcp_posture.context import Target
    from mcp_posture.engine import ScanOptions, scan_target

    flow = Flow()
    token = flow.run().access_token
    opts = ScanOptions(
        net=FAST_NET, tls_probe=False, token=token, transport_factory=lambda: flow.router
    )
    result = asyncio.run(scan_target(Target(url=MCP_URL), opts))
    assert result.auth_required and result.transport == "streamable-http"
    assert os.environ.get("MCP_TOKEN") is None  # nothing was exported anywhere


# --- edge cases ---------------------------------------------------------------------------


def rogue_app(token_body: dict[str, Any] | None = None, register_body: Any = None) -> Starlette:
    """Endpoints that misbehave on purpose, on https://rogue.test."""
    import json

    async def token(request: Request) -> Response:
        return Response(json.dumps(token_body or {}), media_type="application/json")

    async def register(request: Request) -> Response:
        return Response(
            json.dumps(register_body or {}), status_code=201, media_type="application/json"
        )

    async def unregister(request: Request) -> Response:
        return Response(status_code=500)

    return Starlette(
        routes=[
            Route("/token", token, methods=["POST"]),
            Route("/register", register, methods=["POST"]),
            Route("/register/c1", unregister, methods=["DELETE"]),
        ]
    )


def rogue(**metadata: str) -> AsProfile:
    return AsProfile(metadata={**secure_as_metadata(), **metadata})


def test_token_response_without_token_and_narrower_scope() -> None:
    no_token = {"https://rogue.test": rogue_app(token_body={"token_type": "Bearer"})}
    with pytest.raises(LoginError, match="no access_token"):
        Flow(auth=rogue(token_endpoint="https://rogue.test/token"), extra=no_token).run()
    narrow = {
        "https://rogue.test": rogue_app(
            token_body={"access_token": GOOD_TOKEN, "token_type": "bearer", "scope": "other"}
        )
    }
    result = Flow(auth=rogue(token_endpoint="https://rogue.test/token"), extra=narrow).run()
    assert any("narrower; missing: mcp:tools" in w for w in result.warnings)


def test_registration_anomalies() -> None:
    meta = {"registration_endpoint": "https://rogue.test/register"}
    empty = {"https://rogue.test": rogue_app(register_body={})}
    with pytest.raises(LoginError, match="no client_id"):
        Flow(auth=rogue(**meta), extra=empty).run(LoginOptions(register=True))
    failing_delete = {
        "https://rogue.test": rogue_app(
            register_body={
                "client_id": "c1",
                "registration_client_uri": "https://rogue.test/register/c1",
                "registration_access_token": "reg-0123456789abcdef",
            },
            token_body={"access_token": GOOD_TOKEN, "token_type": "Bearer"},
        )
    }
    auth = replace(
        rogue(**meta, token_endpoint="https://rogue.test/token"), pre_registered=frozenset({"c1"})
    )
    flow = Flow(auth=auth, extra=failing_delete)
    flow.run(LoginOptions(register=True))
    assert any("Could not delete the registered client c1" in m for m in flow.messages)


def test_token_endpoint_errors() -> None:
    with pytest.raises(LoginError) as down:
        Flow(auth=rogue(token_endpoint="https://down.test/token")).run()
    assert down.value.unreachable
    from mcp_posture.login import _json_or_error
    from mcp_posture.net import HttpExchange

    bad = HttpExchange(
        "POST",
        "https://as.test/token",
        status=400,
        headers=(("content-type", "application/json"),),
        body=b'{"error": "invalid_grant", "error_description": "expired"}',
    )
    with pytest.raises(LoginError, match=r"HTTP 400\): invalid_grant expired"):
        _json_or_error(bad, "token request")


def test_confidential_pre_registered_client_with_client_secret_post() -> None:
    flow = Flow(auth=rogue(token_endpoint_auth_methods_supported=["client_secret_post"]))  # type: ignore[arg-type]
    with pytest.raises(LoginError, match="only sent to an authorization server you name"):
        flow.run(LoginOptions(client_id=PRE_CLIENT, client_secret="pre-secret-0123456789"))
    flow.run(
        LoginOptions(
            client_id=PRE_CLIENT, client_secret="pre-secret-0123456789", authorization_server=ISSUER
        )
    )
    assert flow.seen("token")[0]["client_secret"] == "pre-secret-0123456789"
    assert flow.redactor.redact("pre-secret-0123456789") == MASK


def test_metadata_and_challenge_gaps() -> None:
    with pytest.raises(LoginError, match="has no token_endpoint"):
        Flow(
            auth=AsProfile(
                metadata={k: v for k, v in secure_as_metadata().items() if k != "token_endpoint"}
            )
        ).run()
    with pytest.raises(LoginError, match="without a Bearer challenge"):
        Flow(McpProfile(challenge=None)).run()
    with pytest.raises(LoginError, match="lists no authorization server"):
        Flow(McpProfile(prm={**secure_prm(), "authorization_servers": []})).run()
    with pytest.raises(LoginError, match="no authorization server metadata"):
        Flow(auth=AsProfile(metadata=None)).run()


def test_prm_at_the_root_may_name_the_origin() -> None:
    root_prm = {**secure_prm(), "resource": "https://mcp.test"}
    mcp = McpProfile(prm=root_prm, prm_variants=frozenset({"root"}), challenge="Bearer")
    result = Flow(mcp).run()
    assert result.resource == "https://mcp.test"
    assert Flow(mcp).seen("token") == []  # a fresh flow saw nothing


def test_legacy_server_issuer_mismatch_and_default_endpoints() -> None:
    wrong = McpProfile(
        revision="2025-03-26",
        prm=None,
        challenge="Bearer",
        legacy_as_metadata=secure_as_metadata(issuer="https://elsewhere.test"),
    )
    with pytest.raises(LoginError, match=re.escape("!= 'https://mcp.test'")):
        Flow(wrong).run()
    defaults = McpProfile(
        revision="2025-03-26", prm=None, challenge="Bearer", authorization_server_paths=True
    )
    flow = Flow(defaults, browser=False)
    with pytest.raises(LoginError, match="no authorization response"):
        flow.run(LoginOptions(client_id=PRE_CLIENT, timeout=0.3))
    assert any("https://mcp.test/authorize?" in m for m in flow.messages)


def test_cimd_fetch_failure_and_port_conflict() -> None:
    with pytest.raises(LoginError, match="cannot fetch the client metadata document"):
        Flow().run(LoginOptions(client_metadata_url="https://client.test/missing.json"))
    fixed = {**good_cimd(), "redirect_uris": ["http://127.0.0.1:41234/callback"]}
    with pytest.raises(LoginError, match="registers port 41234, not --port 5000"):
        Flow(extra={"https://client.test": cimd_app(fixed)}).run(
            LoginOptions(client_metadata_url=CIMD_URL, port=5000)
        )


def test_callback_without_code() -> None:
    flow = Flow()

    async def browse(url: str) -> None:
        from urllib.parse import parse_qs, urlsplit

        q = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
        async with httpx.AsyncClient(trust_env=False) as c:
            await c.get(f"{q['redirect_uri']}?state={q['state']}&iss={ISSUER}")

    flow.ui.open_url = browse
    with pytest.raises(LoginError, match="has no code"):
        flow.run()


def test_helpers() -> None:
    from mcp_posture.login import _jwt_audience, _str_list, _vet_endpoint
    from mcp_posture.net import NetSettings

    assert _jwt_audience("a.b") is None
    assert _jwt_audience("a.!!!.c") is None
    assert _jwt_audience("e30.e30.c") is None  # no aud
    assert _jwt_audience("e30.eyJhdWQiOjF9.c") == []  # aud = 1
    assert _jwt_audience("e30.eyJhdWQiOlsieCIsMV19.c") == ["x"]
    assert _str_list("nope") == ()
    lab = NetSettings(allow_private=True)
    assert _vet_endpoint("token_endpoint", "http://127.0.0.1:9/token", lab).startswith("http://")
    with pytest.raises(LoginError):
        _vet_endpoint("token_endpoint", "http://127.0.0.1:9/token", NetSettings())


def test_callback_server_lifecycle() -> None:
    import socket

    async def go() -> None:
        server = CallbackServer("s")
        with pytest.raises(RuntimeError):
            _ = server.port
        with pytest.raises(RuntimeError):
            await server.wait(0.1)
        busy = socket.socket()
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        try:
            with pytest.raises(LoginError, match="cannot listen"):
                await CallbackServer("s", busy.getsockname()[1]).start()
        finally:
            busy.close()
        await server.start()
        _, writer = await asyncio.open_connection("127.0.0.1", server.port)
        writer.write(b"GET /callback HTTP/1.1\r\n")  # no end of head, then hang up
        writer.close()
        await asyncio.sleep(0.05)
        await server.close()

    asyncio.run(go())


# --- review regressions ---------------------------------------------------------------------


def test_cli_output_neutralizes_escapes_and_redacts_echoed_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    esc = chr(0x1B)

    def hostile(url: str, opts: LoginOptions, net: Any, redactor: Redactor) -> LoginResult:
        redactor.add("pre-secret-0123456789")
        raise LoginError(
            f"denied: {esc}]8;;https://evil.test/{esc}\\click [b]x[/b] pre-secret-0123456789"
        )

    monkeypatch.setattr(cli, "run_login", hostile)
    result = runner.invoke(cli.app, ["login", MCP_URL])
    assert result.exit_code == 1
    assert esc not in result.stderr and "<U+001B>" in result.stderr
    assert "pre-secret-0123456789" not in result.stderr and MASK in result.stderr
    assert "[b]x[/b]" in result.stderr  # shown literally, not interpreted as markup


@pytest.mark.parametrize(
    ("auth", "message"),
    [
        (
            AsProfile(
                metadata={
                    **secure_as_metadata(),
                    "authorization_endpoint": "https://as.test/a" + chr(0x1B) + "]8;;x",
                }
            ),
            "control characters",
        ),
        (
            AsProfile(
                metadata={**secure_as_metadata(), "token_endpoint": "https://as.test/t oken"}
            ),
            "whitespace",
        ),
    ],
)
def test_endpoints_with_controls_or_spaces_are_refused(auth: AsProfile, message: str) -> None:
    with pytest.raises(LoginError, match=message):
        Flow(auth=auth).run()


def test_issuer_must_be_https_and_resource_a_string() -> None:
    http_as = AsProfile(
        issuer="http://as.test", metadata=secure_as_metadata(issuer="http://as.test")
    )
    prm = {**secure_prm(), "authorization_servers": ["http://as.test"]}
    with pytest.raises(LoginError, match=r"issuer .* is not an https URL"):
        Flow(McpProfile(prm=prm), http_as).run()
    with pytest.raises(LoginError, match="does not match"):
        Flow(McpProfile(prm={**secure_prm(), "resource": [MCP_URL]})).run()


def test_offline_access_is_never_requested_by_default() -> None:
    mcp = McpProfile(
        challenge=f'Bearer resource_metadata="{PRM_URL}", scope="mcp:tools offline_access"'
    )
    flow = Flow(mcp)
    flow.run()
    assert flow.seen("authorize")[0]["scope"] == "mcp:tools"


def test_callback_server_drops_connections_beyond_the_cap() -> None:
    from mcp_posture.login import MAX_CALLBACK_CONNECTIONS

    async def go() -> int:
        server = CallbackServer("s")
        await server.start()
        idle = [
            await asyncio.open_connection("127.0.0.1", server.port)
            for _ in range(MAX_CALLBACK_CONNECTIONS)
        ]
        await asyncio.sleep(0.05)
        reader, extra = await asyncio.open_connection("127.0.0.1", server.port)
        dropped = await asyncio.wait_for(reader.read(), 2)  # closed at once: EOF, no response
        for _, w in [*idle, (reader, extra)]:
            w.close()
        await server.close()
        return len(dropped)

    assert asyncio.run(go()) == 0


def test_token_file_write_failure_leaves_nothing(
    fake_login: list[LoginOptions], tmp_path: Path
) -> None:
    locked = tmp_path / "ro"
    locked.mkdir()
    target = locked / "token"
    target.write_text("old\n")
    target.chmod(0o600)
    locked.chmod(0o500)  # no new files (the atomic-replace temp file) in here
    try:
        result = runner.invoke(cli.app, ["login", MCP_URL, "--token-file", str(target)])
    finally:
        locked.chmod(0o700)
    assert result.exit_code == 2 and "cannot write" in result.stderr
    assert sorted(p.name for p in locked.iterdir()) == ["token"]
    assert target.read_text() == "old\n"


# --- mcp-posture's own client metadata document ------------------------------------------------

DOC_PATH = Path(__file__).parent.parent / "docs" / "oauth" / "client.json"


def published_client_app() -> Starlette:
    async def doc(request: Request) -> Response:
        return Response(DOC_PATH.read_bytes(), media_type="application/json")

    return Starlette(routes=[Route("/mcp-posture/oauth/client.json", doc)])


def test_published_client_document_is_clean_and_matches_the_default() -> None:
    import json

    from mcp_posture.cimd_lint import LintInput, lint
    from mcp_posture.login import DEFAULT_CLIENT_METADATA_URL
    from mcp_posture.models import Severity

    doc = json.loads(DOC_PATH.read_text(encoding="utf-8"))
    assert doc["client_id"] == DEFAULT_CLIENT_METADATA_URL
    assert "http://127.0.0.1/callback" in doc["redirect_uris"]
    findings = lint(
        LintInput(
            source=str(DOC_PATH),
            document=doc,
            client_id_url=DEFAULT_CLIENT_METADATA_URL,
            raw_size=DOC_PATH.stat().st_size,
        )
    )
    assert not [f for f in findings if f.severity.at_least(Severity.LOW)], findings


def test_default_client_is_used_when_the_server_supports_cimd() -> None:
    from mcp_posture.login import DEFAULT_CLIENT_METADATA_URL

    flow = Flow(extra={"https://batou9150.github.io": published_client_app()})
    result = flow.run(LoginOptions())
    assert result.strategy == "cimd" and result.client_id == DEFAULT_CLIENT_METADATA_URL
    assert flow.seen("register") == []  # nothing created on the authorization server


def test_explicit_register_beats_the_default_client() -> None:
    flow = Flow(
        auth=AsProfile(metadata=DCR_METADATA),
        extra={"https://batou9150.github.io": published_client_app()},
    )
    assert flow.run(LoginOptions(register=True)).strategy == "dcr"


def test_default_client_unavailable_falls_back_to_registration() -> None:
    flow = Flow(auth=AsProfile(metadata=DCR_METADATA), confirm=lambda q: True)
    assert flow.run(LoginOptions()).strategy == "dcr"
    assert any("client metadata document is unavailable" in m for m in flow.messages)
