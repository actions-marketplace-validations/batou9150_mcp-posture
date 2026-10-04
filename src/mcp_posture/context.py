"""Immutable scan context: everything collected about one target, handed to every check."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal
from urllib.parse import urlsplit

from mcp_posture.models import Confidence, Evidence, Finding, Severity, SpecRevision
from mcp_posture.net import HttpExchange, TlsProbe

FrozenJson = Mapping[str, Any]


def freeze(value: Any) -> Any:
    """Recursively turn dicts into read-only mappings and lists into tuples."""
    if isinstance(value, dict):
        return MappingProxyType({k: freeze(v) for k, v in value.items()})
    if isinstance(value, list | tuple):
        return tuple(freeze(v) for v in value)
    return value


def thaw(value: Any) -> Any:
    """Inverse of :func:`freeze`, for hashing and serialization."""
    if isinstance(value, Mapping):
        return {k: thaw(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [thaw(v) for v in value]
    return value


@dataclass(frozen=True)
class Challenge:
    scheme: str
    params: Mapping[str, str]
    token68: str | None = None

    def get(self, name: str) -> str | None:
        return self.params.get(name.lower())


@dataclass(frozen=True)
class Target:
    url: str
    name: str | None = None
    source: str = "cli"

    @property
    def origin(self) -> str:
        p = urlsplit(self.url)
        return f"{p.scheme}://{p.netloc}"


@dataclass(frozen=True)
class MetadataFetch:
    """One attempt at fetching a well-known metadata document."""

    variant: str
    url: str
    exchange: HttpExchange
    document: FrozenJson | None
    expected_id: str | None = None

    @property
    def found(self) -> bool:
        return self.document is not None


@dataclass(frozen=True)
class AuthServerInfo:
    issuer: str
    fetches: tuple[MetadataFetch, ...]

    @property
    def metadata(self) -> MetadataFetch | None:
        return next((f for f in self.fetches if f.found), None)

    @property
    def document(self) -> FrozenJson | None:
        m = self.metadata
        return m.document if m else None


SurfaceKind = Literal["tool", "prompt", "resource", "resource_template"]


@dataclass(frozen=True)
class SurfaceItem:
    kind: SurfaceKind
    name: str
    definition: FrozenJson

    @property
    def location(self) -> str:
        return f"{self.kind}:{self.name}"


TransportKind = Literal["streamable-http", "legacy-sse", "unknown"]


@dataclass(frozen=True)
class McpProbe:
    transport: TransportKind = "unknown"
    era: Literal["modern", "handshake", "unknown"] = "unknown"
    negotiated_version: str | None = None
    server_info: FrozenJson | None = None
    auth_required: bool = False
    unauth_exchange: HttpExchange | None = None
    challenges: tuple[Challenge, ...] = ()
    session_ids: tuple[str, ...] = ()
    legacy_endpoint: str | None = None
    surface_listed: bool = False
    surface_listed_unauthenticated: bool = False
    surface: tuple[SurfaceItem, ...] = ()
    token_rejected: bool = False
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuthDiscovery:
    prm_fetches: tuple[MetadataFetch, ...] = ()
    authorization_servers: tuple[AuthServerInfo, ...] = ()
    legacy_as: AuthServerInfo | None = None
    legacy_fallback_endpoints: tuple[HttpExchange, ...] = ()

    @property
    def prm(self) -> MetadataFetch | None:
        """The PRM document a client would use: WWW-Authenticate first, then well-known order."""
        return next((f for f in self.prm_fetches if f.found), None)


@dataclass(frozen=True)
class ScanContext:
    target: Target
    revision: SpecRevision
    revision_source: Literal["pinned", "negotiated", "default"]
    active: bool
    token_provided: bool
    mcp: McpProbe
    auth: AuthDiscovery
    exchanges: tuple[HttpExchange, ...]
    tls: tuple[TlsProbe, ...] = ()
    plain_http: tuple[HttpExchange, ...] = ()
    error_probe: HttpExchange | None = None
    extras: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    @property
    def url(self) -> str:
        return self.target.url

    def finding(
        self,
        meta_id: str,
        message: str,
        *,
        location: str | None = None,
        key: str = "",
        evidence: tuple[Evidence, ...] | list[Evidence] = (),
        severity: Severity | None = None,
        confidence: Confidence | None = None,
    ) -> Finding:
        from mcp_posture.registry import REGISTRY

        meta = REGISTRY[meta_id].meta
        return Finding(
            check_id=meta.id,
            title=meta.title,
            severity=severity or meta.severity,
            confidence=confidence or meta.confidence,
            target=self.target.url,
            location=location or self.target.url,
            message=message,
            key=key,
            evidence=tuple(evidence),
        )


def exchange_evidence(ex: HttpExchange, summary: str, excerpt_chars: int = 300) -> Evidence:
    excerpt = ex.error or ex.text[:excerpt_chars] or None
    return Evidence(summary=summary, request=ex.describe(), status=ex.status, excerpt=excerpt)
