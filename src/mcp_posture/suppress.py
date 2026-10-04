"""Suppressions (``.mcp-posture-ignore``): justified, scoped, optionally expiring.

[[ignore]]
check = "MCPP-ASM09"                       # required; short form "ASM09" also accepted
target = "https://mcp.example.com/*"       # optional glob, default "*"
location = "*"                             # optional glob on the finding location
justification = "DCR is intentionally open for our public client registry"  # required
expires = 2026-12-31                       # optional; expired rules resurface the finding
"""

from __future__ import annotations

import fnmatch
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from mcp_posture.models import Finding, SuppressionInfo

DEFAULT_IGNORE_FILE = ".mcp-posture-ignore"
MIN_JUSTIFICATION = 10


class SuppressionError(Exception):
    pass


@dataclass(frozen=True)
class Suppression:
    check: str
    justification: str
    target: str = "*"
    location: str = "*"
    expires: date | None = None

    def matches(self, f: Finding) -> bool:
        return (
            f.check_id == self.check
            and fnmatch.fnmatchcase(f.target, self.target)
            and fnmatch.fnmatchcase(f.location, self.location)
        )


def parse_suppressions(text: str, source: str = DEFAULT_IGNORE_FILE) -> list[Suppression]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise SuppressionError(f"{source}: invalid TOML: {e}") from e
    unknown = set(data) - {"ignore"}
    if unknown:
        raise SuppressionError(f"{source}: unknown top-level keys {sorted(unknown)}")
    entries = data.get("ignore", [])
    if not isinstance(entries, list):
        raise SuppressionError(f"{source}: `ignore` must be an array of tables ([[ignore]])")
    out = []
    for n, entry in enumerate(entries, 1):
        where = f"{source}: [[ignore]] #{n}"
        if not isinstance(entry, dict):
            raise SuppressionError(f"{where} is not a table")
        extra = set(entry) - {"check", "target", "location", "justification", "expires"}
        if extra:
            raise SuppressionError(f"{where}: unknown keys {sorted(extra)}")
        check = str(entry.get("check", "")).strip().upper()
        if not check:
            raise SuppressionError(f"{where}: `check` is required")
        if not check.startswith("MCPP-"):
            check = f"MCPP-{check}"
        justification = str(entry.get("justification", "")).strip()
        if len(justification) < MIN_JUSTIFICATION:
            raise SuppressionError(
                f"{where}: `justification` is required (at least {MIN_JUSTIFICATION} characters)"
            )
        expires = entry.get("expires")
        if expires is not None and not isinstance(expires, date):
            raise SuppressionError(f"{where}: `expires` must be a TOML date, e.g. 2026-12-31")
        out.append(
            Suppression(
                check=check,
                justification=justification,
                target=str(entry.get("target", "*")),
                location=str(entry.get("location", "*")),
                expires=expires,
            )
        )
    return out


def load_suppressions(path: Path) -> list[Suppression]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise SuppressionError(f"cannot read {path}: {e.strerror}") from e
    return parse_suppressions(text, str(path))


def apply_suppressions(
    findings: Iterable[Finding], rules: Iterable[Suppression], today: date
) -> list[Finding]:
    rules = list(rules)
    out = []
    for f in findings:
        matching = [r for r in rules if r.matches(f)]
        if not matching:
            out.append(f)
            continue
        # Prefer a rule that is still valid; otherwise report the expired one.
        active = [r for r in matching if r.expires is None or r.expires >= today]
        rule = active[0] if active else matching[0]
        info = SuppressionInfo(
            justification=rule.justification,
            expires=rule.expires.isoformat() if rule.expires else None,
            expired=not active,
        )
        out.append(f.model_copy(update={"suppression": info}))
    return out
