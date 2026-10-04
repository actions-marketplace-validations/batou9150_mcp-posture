"""Check catalogue. Checks register with :func:`check`; IDs are stable and never reused."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from mcp_posture.models import (
    ALL_REVISIONS,
    CheckMeta,
    CheckMode,
    Confidence,
    Finding,
    Reference,
    Severity,
    SpecRevision,
)

if TYPE_CHECKING:
    from mcp_posture.context import ScanContext

CheckFn = Callable[["ScanContext"], Iterable[Finding]]


@dataclass(frozen=True)
class RegisteredCheck:
    meta: CheckMeta
    fn: CheckFn

    def applies_to(self, revision: SpecRevision) -> bool:
        return revision in self.meta.revisions


REGISTRY: dict[str, RegisteredCheck] = {}

# IDs that existed in a released version and were removed. Never reuse them.
RETIRED_IDS: frozenset[str] = frozenset()


def check(
    *,
    id: str,
    title: str,
    severity: Severity,
    confidence: Confidence = Confidence.HIGH,
    revisions: Iterable[SpecRevision] = ALL_REVISIONS,
    references: Iterable[tuple[str, str]] = (),
    rationale: str,
    remediation: str,
    mode: CheckMode = "passive",
) -> Callable[[CheckFn], CheckFn]:
    if id in REGISTRY:
        raise ValueError(f"duplicate check id {id}")
    if id in RETIRED_IDS:
        raise ValueError(f"check id {id} is retired and must not be reused")
    family = id.removeprefix("MCPP-").rstrip("0123456789")
    meta = CheckMeta(
        id=id,
        family=family,
        title=title,
        severity=severity,
        confidence=confidence,
        revisions=tuple(revisions),
        references=tuple(Reference(title=t, url=u) for t, u in references),
        rationale=_dedent(rationale),
        remediation=_dedent(remediation),
        mode=mode,
    )

    def decorator(fn: CheckFn) -> CheckFn:
        REGISTRY[id] = RegisteredCheck(meta=meta, fn=fn)
        return fn

    return decorator


def _dedent(text: str) -> str:
    return " ".join(line.strip() for line in text.strip().splitlines())


def load_all() -> dict[str, RegisteredCheck]:
    """Import every check module so the registry is complete."""
    from mcp_posture import checks  # noqa: F401

    return REGISTRY


def catalogue() -> list[CheckMeta]:
    return [REGISTRY[k].meta for k in sorted(load_all())]


ERROR_CHECK_ID = "MCPP-ERR00"
