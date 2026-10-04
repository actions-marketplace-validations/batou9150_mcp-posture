"""Catalogue invariants: stable IDs, complete docs fields, and test coverage per check."""

from __future__ import annotations

import re
from pathlib import Path

from mcp_posture.models import Severity
from mcp_posture.registry import catalogue, load_all

TESTS = Path(__file__).parent
MARK = re.compile(r"mark\.check\(\s*\"(positive|negative)\"((?:\s*,\s*\"MCPP-[A-Z]+\d{2}\")+)")


def _marked() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {"positive": set(), "negative": set()}
    for path in TESTS.glob("test_*.py"):
        for kind, ids in MARK.findall(path.read_text(encoding="utf-8")):
            out[kind].update(re.findall(r"MCPP-[A-Z]+\d{2}", ids))
    return out


def test_every_check_has_positive_and_negative_tests() -> None:
    marked = _marked()
    registered = set(load_all())
    assert registered - marked["positive"] == set(), "checks without a positive test"
    assert registered - marked["negative"] == set(), "checks without a negative test"
    assert (marked["positive"] | marked["negative"]) - registered == set(), "unknown ids in marks"


def test_catalogue_entries_are_complete() -> None:
    metas = catalogue()
    assert len({m.id for m in metas}) == len(metas)
    for m in metas:
        assert m.family in m.id and m.title and m.rationale and m.remediation, m.id
        assert m.references, f"{m.id} has no reference"
        assert all(r.url.startswith("https://") for r in m.references), m.id
        assert m.revisions, f"{m.id} applies to no revision"
        assert m.severity in Severity
        assert "  " not in m.rationale


def test_families_are_known() -> None:
    families = {m.family for m in catalogue()}
    assert families <= {"TRN", "AUTHN", "PRM", "ASM", "CIMD", "SCP", "TOOL", "PIN", "ACT"}


def test_repository_has_no_invisible_characters() -> None:
    """Trojan Source hygiene: payloads in tests must be written as escapes, never literally."""
    import unicodedata

    root = TESTS.parent
    offenders = []
    for folder in ("src", "tests", "scripts", "docs"):
        for path in (root / folder).rglob("*"):
            if path.suffix not in {".py", ".md", ".toml", ".json", ".txt", ".yml", ".yaml"}:
                continue
            text = path.read_text(encoding="utf-8")
            bad = {
                c
                for c in text
                if unicodedata.category(c) in ("Cf", "Co")
                or (unicodedata.category(c) == "Cc" and c not in "\n\r\t")
            }
            if bad:
                offenders.append(f"{path.relative_to(root)}: {sorted(hex(ord(c)) for c in bad)}")
    assert offenders == []
