"""Markdown pages for the check catalogue, generated from the registry (docs never drift)."""

from __future__ import annotations

from collections.abc import Iterable

from mcp_posture.models import CheckMeta, SpecRevision

FAMILIES = {
    "TRN": "Transport",
    "AUTHN": "Authentication challenge",
    "PRM": "Protected Resource Metadata (RFC 9728)",
    "ASM": "Authorization Server Metadata (RFC 8414 / OIDC)",
    "CIMD": "Client ID Metadata Documents",
    "SCP": "Scopes",
    "TOOL": "Tool surface",
    "PIN": "Rug-pull pinning",
    "ACT": "Active checks",
}
MODES = {
    "passive": "passive (default scan)",
    "active": "active (`--active` only)",
    "lint": "`mcp-posture cimd lint` only",
}


def revision_span(revisions: tuple[SpecRevision, ...]) -> str:
    if len(revisions) == len(SpecRevision):
        return "all"
    if len(revisions) == 1:
        return revisions[0].value
    if revisions[-1] == SpecRevision.latest():
        return f"{revisions[0].value} and later"
    return f"{revisions[0].value} to {revisions[-1].value}"


def check_page(meta: CheckMeta) -> str:
    refs = "\n".join(f"- [{r.title}]({r.url})" for r in meta.references)
    return f"""# {meta.id}: {meta.title}

| | |
|---|---|
| Family | {FAMILIES.get(meta.family, meta.family)} |
| Default severity | `{meta.severity.value}` |
| Confidence | `{meta.confidence.value}` |
| Mode | {MODES[meta.mode]} |
| Spec revisions | {revision_span(meta.revisions)} |

## Why it matters

{meta.rationale}

## Remediation

{meta.remediation}

## References

{refs}

## Suppressing

```toml
# .mcp-posture-ignore
[[ignore]]
check = "{meta.id}"
target = "https://mcp.example.com/*"
justification = "Why this is acceptable here"
expires = 2026-12-31
```
"""


def index_page(metas: Iterable[CheckMeta]) -> str:
    metas = list(metas)
    lines = [
        "# Check catalogue",
        "",
        f"{len(metas)} rules. IDs are stable and never reused. Severities are defaults; some "
        "checks adjust them per spec revision or evidence.",
        "",
    ]
    for family, label in FAMILIES.items():
        rows = [m for m in metas if m.family == family]
        if not rows:
            continue
        lines += [
            f"## {label}",
            "",
            "| ID | Title | Severity | Mode | Revisions |",
            "|---|---|---|---|---|",
        ]
        lines += [
            f"| [{m.id}]({m.docs_slug}.md) | {m.title} | `{m.severity.value}` | {m.mode} | "
            f"{revision_span(m.revisions)} |"
            for m in rows
        ]
        lines.append("")
    return "\n".join(lines)
