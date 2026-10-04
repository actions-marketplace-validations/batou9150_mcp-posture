"""Small helpers shared by check modules."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

from mcp_posture.context import AuthServerInfo, FrozenJson, ScanContext
from mcp_posture.net import is_loopback_host


def str_list(value: Any) -> list[str]:
    """A JSON array of strings (frozen as a tuple), or [] for anything else."""
    if isinstance(value, tuple | list):
        return [v for v in value if isinstance(v, str)]
    return []


def is_https(url: str) -> bool:
    return urlsplit(url).scheme == "https"


def is_loopback_url(url: str) -> bool:
    return is_loopback_host(urlsplit(url).hostname or "")


def auth_servers(ctx: ScanContext) -> Iterator[tuple[AuthServerInfo, FrozenJson]]:
    """Every authorization server whose metadata was found, including the 2025-03-26 one."""
    servers = list(ctx.auth.authorization_servers)
    if ctx.auth.legacy_as is not None:
        servers.append(ctx.auth.legacy_as)
    for s in servers:
        doc = s.document
        if doc is not None:
            yield s, doc


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)
