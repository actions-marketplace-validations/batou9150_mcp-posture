"""Core data model: severities, spec revisions, checks, findings and the versioned report."""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field

REPORT_SCHEMA_VERSION = "1.0"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def at_least(self, other: Severity) -> bool:
        return self.rank >= other.rank


_SEVERITY_RANK = {s: i for i, s in enumerate(Severity)}


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SpecRevision(StrEnum):
    """MCP specification revisions the scanner knows about, oldest first."""

    R2025_03_26 = "2025-03-26"
    R2025_06_18 = "2025-06-18"
    R2025_11_25 = "2025-11-25"
    R2026_07_28 = "2026-07-28"

    @property
    def order(self) -> int:
        return _REVISION_INDEX[self]

    def at_least(self, other: SpecRevision) -> bool:
        return self.order >= other.order

    @property
    def stateless(self) -> bool:
        """2026-07-28 removed sessions, ``initialize`` and the GET stream."""
        return self.at_least(SpecRevision.R2026_07_28)

    @classmethod
    def latest(cls) -> SpecRevision:
        return list(cls)[-1]

    @classmethod
    def parse(cls, value: str) -> SpecRevision | None:
        try:
            return cls(value)
        except ValueError:
            return None


_REVISION_INDEX = {r: i for i, r in enumerate(SpecRevision)}
ALL_REVISIONS: tuple[SpecRevision, ...] = tuple(SpecRevision)


def revisions_from(first: SpecRevision) -> tuple[SpecRevision, ...]:
    return tuple(r for r in SpecRevision if r.at_least(first))


def revisions_until(last: SpecRevision) -> tuple[SpecRevision, ...]:
    return tuple(r for r in SpecRevision if last.at_least(r))


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Reference(_Frozen):
    title: str
    url: str


CheckMode = Literal["passive", "active", "lint"]


class CheckMeta(_Frozen):
    """Catalogue entry. The registry is the single source of truth for docs and SARIF rules."""

    id: str = Field(pattern=r"^MCPP-[A-Z]+\d{2}$")
    family: str
    title: str
    severity: Severity
    confidence: Confidence
    revisions: tuple[SpecRevision, ...]
    references: tuple[Reference, ...]
    rationale: str
    remediation: str
    mode: CheckMode = "passive"

    @property
    def docs_slug(self) -> str:
        return self.id.lower()


class Evidence(_Frozen):
    """What the scanner observed. Strings are redacted again at render time."""

    summary: str
    request: str | None = None
    status: int | None = None
    excerpt: str | None = None


class SuppressionInfo(_Frozen):
    justification: str
    expires: str | None = None
    expired: bool = False


class Finding(_Frozen):
    check_id: str
    title: str
    severity: Severity
    confidence: Confidence
    target: str
    location: str
    message: str
    key: str = ""
    evidence: tuple[Evidence, ...] = ()
    suppression: SuppressionInfo | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fingerprint(self) -> str:
        raw = f"{self.check_id}\x00{self.target}\x00{self.location}\x00{self.key}".encode()
        return hashlib.sha256(raw).hexdigest()[:32]

    @property
    def suppressed(self) -> bool:
        return self.suppression is not None and not self.suppression.expired

    def sort_key(self) -> tuple[str, int, str, str]:
        return (self.target, -self.severity.rank, self.check_id, self.fingerprint)


RevisionSource = Literal["pinned", "negotiated", "default"]


class TargetResult(_Frozen):
    target: str
    name: str | None = None
    source: str = "cli"
    reachable: bool
    error: str | None = None
    spec_revision: SpecRevision
    revision_source: RevisionSource
    transport: str | None = None
    auth_required: bool | None = None
    findings: tuple[Finding, ...] = ()
    not_applicable: tuple[str, ...] = ()


class ToolInfo(_Frozen):
    name: str = "mcp-posture"
    version: str
    information_uri: str = "https://github.com/batou9150/mcp-posture"


class Summary(_Frozen):
    targets: int
    unreachable: int
    findings: dict[str, int]
    suppressed: int


class Report(_Frozen):
    schema_version: Literal["1.0"] = "1.0"
    tool: ToolInfo
    generated_at: datetime | None
    mode: CheckMode
    fail_on: Severity
    targets: tuple[TargetResult, ...]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def summary(self) -> Summary:
        counts = {s.value: 0 for s in Severity}
        suppressed = 0
        for t in self.targets:
            for f in t.findings:
                if f.suppressed:
                    suppressed += 1
                else:
                    counts[f.severity.value] += 1
        return Summary(
            targets=len(self.targets),
            unreachable=sum(1 for t in self.targets if not t.reachable),
            findings=counts,
            suppressed=suppressed,
        )

    def active_findings(self) -> list[Finding]:
        return [f for t in self.targets for f in t.findings if not f.suppressed]
