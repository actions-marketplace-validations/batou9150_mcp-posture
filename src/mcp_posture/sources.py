"""Target sources: discover remote MCP servers declared in MCP client configs.

Only remote (http/https) entries are returned. Headers, env and other values from the
configs are never read into the scan or the report, since they often hold credentials.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from mcp_posture.context import Target

REMOTE_TYPES = frozenset({"http", "streamable-http", "streamablehttp", "sse", "remote"})


class SourceError(Exception):
    pass


def known_config_paths(cwd: Path, home: Path) -> list[tuple[str, Path]]:
    """Project and user-level config files of common MCP clients."""
    paths = [
        ("claude-code-project", cwd / ".mcp.json"),
        ("vscode-workspace", cwd / ".vscode" / "mcp.json"),
        ("cursor-project", cwd / ".cursor" / "mcp.json"),
        ("claude-code-user", home / ".claude.json"),
        ("cursor-user", home / ".cursor" / "mcp.json"),
        ("windsurf-user", home / ".codeium" / "windsurf" / "mcp_config.json"),
    ]
    if sys.platform == "darwin":
        support = home / "Library" / "Application Support"
        paths += [
            ("claude-desktop", support / "Claude" / "claude_desktop_config.json"),
            ("vscode-user", support / "Code" / "User" / "mcp.json"),
        ]
    elif sys.platform == "win32":
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        paths += [
            ("claude-desktop", appdata / "Claude" / "claude_desktop_config.json"),
            ("vscode-user", appdata / "Code" / "User" / "mcp.json"),
        ]
    else:
        config = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
        paths += [
            ("claude-desktop", config / "Claude" / "claude_desktop_config.json"),
            ("vscode-user", config / "Code" / "User" / "mcp.json"),
        ]
    return paths


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas (VS Code configs are JSONC)."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
        elif c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j == -1 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _server_tables(doc: Mapping[str, Any]) -> Iterator[tuple[str, Mapping[str, Any]]]:
    for key in ("mcpServers", "servers"):
        table = doc.get(key)
        if isinstance(table, Mapping):
            yield key, table
    mcp = doc.get("mcp")
    if isinstance(mcp, Mapping) and isinstance(mcp.get("servers"), Mapping):
        yield "mcp.servers", mcp["servers"]
    projects = doc.get("projects")  # ~/.claude.json keeps per-project servers
    if isinstance(projects, Mapping):
        for project, cfg in sorted(projects.items()):
            if isinstance(cfg, Mapping) and isinstance(cfg.get("mcpServers"), Mapping):
                yield f"projects[{project}]", cfg["mcpServers"]


def _remote_url(entry: Mapping[str, Any]) -> str | None:
    for key in ("url", "serverUrl"):
        value = entry.get(key)
        if isinstance(value, str):
            kind = str(entry.get("type", "http")).lower()
            return value if kind in REMOTE_TYPES else None
    # stdio bridges to a remote server, e.g. `npx mcp-remote https://...`
    args = entry.get("args")
    command = str(entry.get("command", ""))
    if isinstance(args, list) and any("mcp-remote" in str(a) for a in [command, *args]):
        for a in args:
            if isinstance(a, str) and a.startswith(("https://", "http://")):
                return a
    return None


def targets_from_config(path: Path) -> list[Target]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise SourceError(f"cannot read {path}: {e.strerror}") from e
    try:
        doc = json.loads(strip_jsonc(text))
    except ValueError as e:
        raise SourceError(f"{path} is not valid JSON: {e}") from e
    if not isinstance(doc, Mapping):
        return []
    out = []
    for table_name, table in _server_tables(doc):
        for name, entry in table.items():
            if not isinstance(entry, Mapping):
                continue
            url = _remote_url(entry)
            if url is None or urlsplit(url).scheme not in ("http", "https"):
                continue
            where = "" if table_name in ("mcpServers", "servers") else f"{table_name}."
            out.append(Target(url=url, name=str(name), source=f"config:{path}#{where}{name}"))
    return out


def discover(specs: list[str], cwd: Path, home: Path) -> list[Target]:
    """``specs`` holds paths, or ``auto`` for every known client config that exists."""
    out: list[Target] = []
    for spec in specs:
        if spec == "auto":
            for _client, path in known_config_paths(cwd, home):
                if path.is_file():
                    try:
                        out.extend(targets_from_config(path))
                    except SourceError:
                        continue  # a broken user config must not stop auto-discovery
        else:
            out.extend(targets_from_config(Path(spec).expanduser()))
    unique: dict[str, Target] = {}
    for t in out:
        unique.setdefault(t.url, t)
    return list(unique.values())


def source_file(target: Target) -> Path | None:
    """The file a target was declared in, for SARIF anchoring."""
    if target.source.startswith("file:"):
        return Path(target.source.removeprefix("file:"))
    if target.source.startswith("config:"):
        return Path(target.source.removeprefix("config:").rsplit("#", 1)[0])
    return None


def line_of(path: Path, needle: str) -> int:
    try:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if needle in line:
                return n
    except OSError:
        pass
    return 1
