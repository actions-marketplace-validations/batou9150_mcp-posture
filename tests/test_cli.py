"""CLI tests, including end-to-end scans against real loopback servers (plain and TLS)."""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import trustme
import uvicorn
from typer.testing import CliRunner

from mcp_posture.cli import app
from tests.fixtures.servers import GOOD_TOKEN, McpProfile, mcp_app, secure_as_metadata

runner = CliRunner()


def invoke(*args: str, env: dict[str, str] | None = None, stdin: str | None = None) -> Any:
    return runner.invoke(app, list(args), env=env, input=stdin)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _Server:
    def __init__(self, app: Any, **ssl: Any) -> None:
        self.port = _free_port()
        config = uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error", **ssl)
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self) -> _Server:
        self.thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started:
            if time.monotonic() > deadline:  # pragma: no cover
                raise RuntimeError("server did not start")
            time.sleep(0.02)
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)


def single_origin_profile(base: str, **changes: Any) -> McpProfile:
    """MCP server, PRM and authorization server metadata all on one loopback origin."""
    prm = {
        "resource": f"{base}/mcp",
        "authorization_servers": [base],
        "scopes_supported": ["mcp:tools"],
        "bearer_methods_supported": ["header"],
    }
    return McpProfile(
        prm=prm,
        challenge=f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource/mcp"',
        legacy_as_metadata=secure_as_metadata(base),
        **changes,
    )


@pytest.fixture
def plain_server() -> Iterator[str]:
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    server = _Server(mcp_app(single_origin_profile(base)))
    server.port = port
    server.server.config.port = port
    with server:
        yield base


def test_version_and_checks_commands() -> None:
    assert invoke("version").stdout.strip()
    listed = invoke("checks", "list")
    assert listed.exit_code == 0 and "MCPP-PRM03" in listed.stdout
    shown = invoke("checks", "show", "mcpp-asm04")
    assert shown.exit_code == 0 and "RFC 7636" in shown.stdout
    assert invoke("checks", "show", "MCPP-NOPE99").exit_code == 2


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ((), "no targets"),
        (("ftp://x",), "not an http(s) URL"),
        (("https://u:p@h/mcp",), "must not embed credentials"),
        (("https://h/mcp", "--spec", "2020-01-01"), "unknown spec"),
        (("https://h/mcp", "--format", "xml"), "unknown format"),
        (("https://h/mcp", "--token-env", "MCPP_UNSET_VAR"), "empty or unset"),
        (("https://h/mcp", "--token-env", "A", "--token-stdin"), "only one of"),
        (("https://h/mcp", "--ca-bundle", "/nonexistent.pem"), "CA bundle not found"),
        (("https://h/mcp", "--concurrency", "0"), "concurrency"),
        (("https://h/mcp", "--token-file", "/nonexistent-token"), "cannot read token file"),
        (("--targets-file", "/nonexistent-targets"), "cannot read targets file"),
    ],
)
def test_usage_errors_exit_2(args: tuple[str, ...], message: str) -> None:
    result = invoke("scan", *args)
    assert result.exit_code == 2
    assert message in result.stderr


def test_token_sources(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.write_text("")
    assert (
        "token file is empty" in invoke("scan", "https://h/mcp", "--token-file", str(empty)).stderr
    )
    assert (
        "no token on stdin" in invoke("scan", "https://h/mcp", "--token-stdin", stdin="\n").stderr
    )


def test_private_target_blocked_by_default_exit_3() -> None:
    result = invoke("scan", "http://127.0.0.1:9/mcp", "--retries", "0", "--format", "json")
    assert result.exit_code == 3
    report = json.loads(result.stdout)
    assert "--allow-private" in report["targets"][0]["error"]


@pytest.mark.network
def test_e2e_plain_http_scan(plain_server: str, tmp_path: Path) -> None:
    targets = tmp_path / "targets.txt"
    targets.write_text(f"# comment\n{plain_server}/mcp\n\n")
    out = tmp_path / "report.json"
    result = invoke(
        "scan",
        "--targets-file",
        str(targets),
        "--allow-private",
        "--format",
        "json",
        "--output",
        str(out),
        "--no-timestamp",
        "--fail-on",
        "critical",
    )
    assert result.exit_code == 0, result.stderr
    report = json.loads(out.read_text())
    [target] = report["targets"]
    assert target["reachable"] and target["auth_required"]
    assert report["generated_at"] is None
    found = {f["check_id"] for f in target["findings"]}
    assert "MCPP-PRM03" not in found and "MCPP-ASM02" not in found
    assert "MCPP-TRN01" not in found  # loopback http is exempt


@pytest.mark.network
def test_e2e_token_is_used_and_redacted(plain_server: str) -> None:
    result = invoke(
        "scan",
        f"{plain_server}/mcp",
        "--allow-private",
        "--token-env",
        "MCPP_TEST_TOKEN",
        "--format",
        "table",
        "-v",
        env={"MCPP_TEST_TOKEN": GOOD_TOKEN},
    )
    assert result.exit_code in (0, 1), result.stderr
    assert GOOD_TOKEN not in result.stdout + result.stderr
    assert "streamable-http" in result.stdout


@pytest.mark.network
def test_e2e_tls_scan(tmp_path: Path) -> None:
    ca = trustme.CA()
    cert = ca.issue_cert("localhost", "127.0.0.1")
    certfile, keyfile, cafile = tmp_path / "cert.pem", tmp_path / "key.pem", tmp_path / "ca.pem"
    cert.cert_chain_pems[0].write_to_path(str(certfile))
    for pem in cert.cert_chain_pems[1:]:
        pem.write_to_path(str(certfile), append=True)
    cert.private_key_pem.write_to_path(str(keyfile))
    ca.cert_pem.write_to_path(str(cafile))
    port = _free_port()
    base = f"https://localhost:{port}"
    server = _Server(
        mcp_app(single_origin_profile(base)),
        ssl_certfile=str(certfile),
        ssl_keyfile=str(keyfile),
    )
    server.port = port
    server.server.config.port = port
    with server:
        ok = invoke(
            "scan", f"{base}/mcp", "--allow-private", "--ca-bundle", str(cafile), "-f", "json"
        )
        untrusted = invoke("scan", f"{base}/mcp", "--allow-private", "-f", "json", "--retries", "0")
    report = json.loads(ok.stdout)
    found = {f["check_id"] for f in report["targets"][0]["findings"]}
    assert report["targets"][0]["reachable"]
    assert not {"MCPP-TRN02", "MCPP-TRN03"} & found
    assert untrusted.exit_code == 3
    assert "certificate" in json.loads(untrusted.stdout)["targets"][0]["error"]
