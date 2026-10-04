"""Docs are generated from the registry; hand-written pages must agree with it."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from mcp_posture.docs import check_page, index_page, revision_span
from mcp_posture.models import SpecRevision
from mcp_posture.registry import catalogue

ROOT = Path(__file__).parent.parent


def test_every_check_has_a_page_linked_from_the_index() -> None:
    metas = catalogue()
    index = index_page(metas)
    for meta in metas:
        assert f"]({meta.docs_slug}.md)" in index
        page = check_page(meta)
        assert page.startswith(f"# {meta.id}: {meta.title}")
        assert meta.remediation in page and all(r.url in page for r in meta.references)


def test_revision_span() -> None:
    assert revision_span(tuple(SpecRevision)) == "all"
    assert revision_span((SpecRevision.R2025_03_26,)) == "2025-03-26"
    assert revision_span(tuple(SpecRevision)[1:]) == "2025-06-18 and later"
    assert revision_span(tuple(SpecRevision)[:3]) == "2025-03-26 to 2025-11-25"


def test_readme_family_counts_match_the_catalogue() -> None:
    counts = Counter(m.family for m in catalogue())
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    table = dict(re.findall(r"^\| `([A-Z]+)` \| (\d+) \|", readme, re.M))
    assert table, "README family table not found"
    assert {k: int(v) for k, v in table.items()} == {k: counts[k] for k in table}
    assert set(table) == set(counts) - {"ACT"}
