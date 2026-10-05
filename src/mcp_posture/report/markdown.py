"""Markdown summary for pull-request comments and GitHub job summaries."""

from __future__ import annotations

import html
import re

from mcp_posture.models import Finding, Report, Severity

DOCS = "https://batou9150.github.io/mcp-posture/checks"
MAX_ROWS_PER_TARGET = 50


def _one_line(text: str) -> str:
    """A blank line would end an HTML block and let the rest be parsed as Markdown."""
    return " ".join(text.split())


def _code(text: str) -> str:
    """Server-controlled text as an inline code span: GitHub renders no links, images,
    mentions or HTML inside it. The delimiter is longer than any backtick run in the text."""
    text = " ".join(text.splitlines()).replace("|", "\\|")  # one table cell, one line
    if not text.strip():
        return ""
    run = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * (run + 1)
    return f"{fence} {text} {fence}"


def _fence(text: str) -> str:
    """A code-block fence that the block's content cannot close."""
    run = max((len(m) for m in re.findall(r"`{3,}", text)), default=0)
    return "`" * max(3, run + 1)


def _row(f: Finding) -> str:
    link = f"[{f.check_id}]({DOCS}/{f.check_id.lower()}/)"
    return f"| {f.severity.value} | {link} | {f.title} | {_code(f.message)} |"


def render(report: Report) -> str:
    s = report.summary
    blocking = sum(1 for f in report.active_findings() if f.severity.at_least(report.fail_on))
    status = "❌" if blocking else ("⚠️" if s.unreachable else "✅")
    lines = [
        f"## {status} mcp-posture: {s.targets} MCP server(s) scanned",
        "",
        "| " + " | ".join(sev.value for sev in reversed(Severity)) + " | suppressed |",
        "|" + "---:|" * (len(Severity) + 1),
        "| "
        + " | ".join(str(s.findings[sev.value]) for sev in reversed(Severity))
        + f" | {s.suppressed} |",
        "",
        f"Mode `{report.mode}` · fail on `{report.fail_on.value}` · "
        f"{blocking} blocking finding(s) · {s.unreachable} unreachable target(s)",
        "",
    ]
    for t in report.targets:
        title = _code(t.target) + (f" ({_code(t.name)})" if t.name else "")
        lines.append(f"### {title}")
        lines.append("")
        if not t.reachable:
            lines += [f"Unreachable: {_code(t.error or 'unknown error')}", ""]
            continue
        lines.append(
            f"Spec `{t.spec_revision.value}` ({t.revision_source}) · transport `{t.transport}`"
            f" · auth {'required' if t.auth_required else '**not required**'}"
        )
        lines.append("")
        active = [f for f in t.findings if not f.suppressed]
        if not active:
            lines += ["No findings.", ""]
        else:
            lines += ["| Severity | Check | Title | Details |", "|---|---|---|---|"]
            lines += [_row(f) for f in active[:MAX_ROWS_PER_TARGET]]
            if len(active) > MAX_ROWS_PER_TARGET:
                lines.append(f"| … | | | {len(active) - MAX_ROWS_PER_TARGET} more |")
            lines.append("")
        changed = [f for f in active if f.check_id == "MCPP-PIN03" and f.evidence]
        for f in changed:
            diff = f.evidence[0].excerpt or ""
            fence = _fence(diff)
            where = html.escape(_one_line(f.location))
            lines += [
                f"<details><summary><code>{where}</code> changed</summary>",
                "",
                f"{fence}diff",
                diff,
                fence,
                "",
                "</details>",
                "",
            ]
        suppressed = [f for f in t.findings if f.suppressed]
        if suppressed:
            lines.append(f"<details><summary>{len(suppressed)} suppressed finding(s)</summary>\n")
            for f in suppressed:
                why = f.suppression.justification if f.suppression else ""
                lines.append(f"- `{f.check_id}` {_code(f.message)}: {_code(why)}")
            lines += ["", "</details>", ""]
    return "\n".join(lines).rstrip() + "\n"
