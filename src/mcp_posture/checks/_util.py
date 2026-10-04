"""Small helpers shared by check modules."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

from mcp_posture.context import AuthServerInfo, FrozenJson, ScanContext, thaw
from mcp_posture.models import Evidence
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


def field_evidence(server: AuthServerInfo, field: str) -> list[Evidence]:
    """The metadata field as served, so findings can be verified without re-fetching."""
    fetch = server.metadata
    if fetch is None or fetch.document is None:
        return []
    value = thaw(fetch.document.get(field, "<absent>"))
    excerpt = json.dumps(value, ensure_ascii=False) if value != "<absent>" else "absent"
    return [
        Evidence(
            summary=field,
            request=fetch.exchange.describe(),
            status=fetch.exchange.status,
            excerpt=excerpt[:300],
        )
    ]
