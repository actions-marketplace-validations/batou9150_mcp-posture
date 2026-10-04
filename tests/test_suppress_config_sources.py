from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from mcp_posture.config import ConfigError, build_config, load_config
from mcp_posture.context import Target
from mcp_posture.models import Confidence, Finding, Severity
from mcp_posture.sources import (
    SourceError,
    discover,
    known_config_paths,
    line_of,
    source_file,
    strip_jsonc,
    targets_from_config,
)
from mcp_posture.suppress import (
    SuppressionError,
    apply_suppressions,
    load_suppressions,
    parse_suppressions,
)


def finding(check: str = "MCPP-ASM09", target: str = "https://a.test/mcp") -> Finding:
    return Finding(
        check_id=check,
        title="t",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        target=target,
        location="https://as.test",
        message="m",
    )


# --- suppressions ------------------------------------------------------------------------

RULES = """
[[ignore]]
check = "ASM09"
target = "https://a.test/*"
justification = "Open DCR is intended for the public registry"

[[ignore]]
check = "MCPP-ASM11"
justification = "Waiting for the vendor fix, tracked in SEC-12"
expires = 2026-01-31
"""


def test_suppressions_apply_and_expire() -> None:
    rules = parse_suppressions(RULES)
    out = apply_suppressions(
        [finding(), finding(target="https://b.test/mcp"), finding("MCPP-ASM11")],
        rules,
        date(2026, 6, 1),
    )
    assert out[0].suppressed and out[0].suppression is not None
    assert not out[1].suppressed and out[1].suppression is None
    expired = out[2]
    assert expired.suppression is not None and expired.suppression.expired
    assert not expired.suppressed
    early = apply_suppressions([finding("MCPP-ASM11")], rules, date(2026, 1, 1))
    assert early[0].suppressed


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[[ignore]]\ncheck='X'", "justification"),
        ("[[ignore]]\njustification='long enough reason'", "`check` is required"),
        ("[[ignore]]\ncheck='X'\njustification='long enough reason'\nexpires='soon'", "TOML date"),
        ("[[ignore]]\ncheck='X'\njustification='long enough reason'\nfoo=1", "unknown keys"),
        ("other = 1", "unknown top-level"),
        ("ignore = 1", "array of tables"),
        ("ignore = [1]", "not a table"),
        ("[[ignore", "invalid TOML"),
    ],
)
def test_suppression_errors(text: str, message: str) -> None:
    with pytest.raises(SuppressionError, match=message):
        parse_suppressions(text)


def test_load_suppressions_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SuppressionError, match="cannot read"):
        load_suppressions(tmp_path / "nope")


# --- config ------------------------------------------------------------------------------


def test_config_precedence_and_relative_paths(tmp_path: Path) -> None:
    (tmp_path / "mcp-posture.toml").write_text(
        '[scan]\nfail_on = "medium"\ntimeout = 3\nca_bundle = "certs/ca.pem"\n'
        'targets = ["https://a.test/mcp"]\n'
    )
    values, path = load_config(None, tmp_path)
    assert path == tmp_path / "mcp-posture.toml"
    assert values["ca_bundle"] == str((tmp_path / "certs/ca.pem").resolve())
    cfg = build_config(values, {"timeout": 7.5, "fail_on": None}, "x")
    assert (
        cfg.timeout == 7.5
        and cfg.fail_on == Severity.MEDIUM
        and cfg.targets == ["https://a.test/mcp"]
    )
    assert load_config(None, tmp_path / "missing") == ({}, None)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[scan]\ntimeout = -1", "timeout"),
        ("[scan]\nspec = '1999-01-01'", "unknown spec"),
        ("[scan]\nbogus = 1", "bogus"),
        ("[other]\nx = 1", "other"),
        ("[scan", "invalid TOML"),
    ],
)
def test_config_errors(tmp_path: Path, text: str, message: str) -> None:
    path = tmp_path / "c.toml"
    path.write_text(text)
    with pytest.raises(ConfigError, match=message):
        values, _ = load_config(path, tmp_path)
        build_config(values, {}, str(path))


def test_config_unreadable(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "missing.toml", tmp_path)


# --- client config sources ---------------------------------------------------------------


def write(path: Path, data: object | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    return path


def test_parse_client_config_variants(tmp_path: Path) -> None:
    claude_code = write(
        tmp_path / "claude.json",
        {
            "mcpServers": {
                "remote": {"type": "http", "url": "https://r.test/mcp", "headers": {"A": "secret"}},
                "local": {"command": "node", "args": ["server.js"]},
                "bridge": {"command": "npx", "args": ["-y", "mcp-remote", "https://b.test/sse"]},
                "weird": {"type": "stdio", "url": "https://ignored.test"},
                "bad": "not a table",
            },
            "projects": {"/w": {"mcpServers": {"p": {"type": "sse", "url": "https://p.test/sse"}}}},
        },
    )
    targets = targets_from_config(claude_code)
    assert [(t.url, t.name) for t in targets] == [
        ("https://r.test/mcp", "remote"),
        ("https://b.test/sse", "bridge"),
        ("https://p.test/sse", "p"),
    ]
    assert targets[2].source.endswith("#projects[/w].p")
    assert all("secret" not in t.source for t in targets)
    vscode = write(
        tmp_path / ".vscode/mcp.json",
        '{\n  // comment\n  "servers": {"gh": {"type": "http", "url": "https://gh.test/mcp",},},\n'
        '  /* block */ "inputs": []\n}',
    )
    assert [t.url for t in targets_from_config(vscode)] == ["https://gh.test/mcp"]
    windsurf = write(
        tmp_path / "w.json", {"mcpServers": {"x": {"serverUrl": "https://w.test/mcp"}}}
    )
    assert [t.url for t in targets_from_config(windsurf)] == ["https://w.test/mcp"]
    settings = write(tmp_path / "s.json", {"mcp": {"servers": {"y": {"url": "http://y.test/mcp"}}}})
    assert [t.url for t in targets_from_config(settings)] == ["http://y.test/mcp"]
    assert targets_from_config(write(tmp_path / "list.json", [1])) == []


def test_auto_discovery(tmp_path: Path) -> None:
    cwd, home = tmp_path / "proj", tmp_path / "home"
    write(cwd / ".mcp.json", {"mcpServers": {"a": {"type": "http", "url": "https://a.test/mcp"}}})
    write(home / ".cursor/mcp.json", {"mcpServers": {"b": {"url": "https://b.test/mcp"}}})
    write(home / ".claude.json", "{broken")
    write(
        home / ".codeium/windsurf/mcp_config.json",
        {"mcpServers": {"dup": {"serverUrl": "https://a.test/mcp"}}},
    )
    found = discover(["auto"], cwd, home)
    assert [t.url for t in found] == ["https://a.test/mcp", "https://b.test/mcp"]
    assert len(known_config_paths(cwd, home)) >= 8


def test_source_errors(tmp_path: Path) -> None:
    with pytest.raises(SourceError, match="cannot read"):
        discover([str(tmp_path / "missing.json")], tmp_path, tmp_path)
    with pytest.raises(SourceError, match="not valid JSON"):
        targets_from_config(write(tmp_path / "x.json", "{"))


def test_strip_jsonc_keeps_strings() -> None:
    text = '{"u": "https://x//y", "c": "/* not a comment */", "e": "a\\"//b"} // tail'
    assert json.loads(strip_jsonc(text)) == {
        "u": "https://x//y",
        "c": "/* not a comment */",
        "e": 'a"//b',
    }
    assert strip_jsonc("[1, /* unterminated") == "[1, "


def test_source_file_and_line(tmp_path: Path) -> None:
    f = write(tmp_path / "targets.txt", "# x\nhttps://a.test/mcp\n")
    assert source_file(Target("u", source=f"file:{f}")) == f
    assert source_file(Target("u", source=f"config:{f}#name")) == f
    assert source_file(Target("u")) is None
    assert line_of(f, "https://a.test/mcp") == 2
    assert line_of(f, "absent") == 1 and line_of(tmp_path / "missing", "x") == 1
