"""Human-readable terminal report (rich)."""

from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from mcp_posture.heuristics import visible as safe
from mcp_posture.models import Report, Severity

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render(report: Report, *, color: bool = False, width: int = 120) -> str:
    buf = StringIO()
    console = Console(file=buf, force_terminal=color, no_color=not color, width=width)
    for t in report.targets:
        header = Text(safe(t.target), style="bold")
        if t.name:
            header.append(f"  ({safe(t.name)})", style="dim")
        console.print(header)
        if not t.reachable:
            console.print(Text(f"  unreachable: {safe(t.error or '')}", style="red"))
            console.print()
            continue
        transport = t.transport
        if transport == "unknown" and t.auth_required:
            transport = "not detected (authentication required; pass a token to probe further)"
        console.print(
            Text(
                f"  spec {t.spec_revision.value} ({t.revision_source}) · transport {transport}"
                f" · auth {'required' if t.auth_required else 'not required'}",
                style="dim",
            )
        )
        findings = [f for f in t.findings if not f.suppressed]
        if not findings:
            console.print(Text("  no findings", style="green"))
            console.print()
            continue
        table = Table(show_header=True, header_style="bold", expand=True, pad_edge=False)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Check", no_wrap=True)
        table.add_column("Finding", ratio=1)
        for f in findings:
            table.add_row(
                Text(f.severity.value, style=SEVERITY_STYLE[f.severity]),
                f.check_id,
                Text(f"{f.title}\n", style="bold") + Text(safe(f.message)),
            )
        console.print(table)
        suppressed = sum(1 for f in t.findings if f.suppressed)
        if suppressed:
            console.print(Text(f"  {suppressed} suppressed finding(s)", style="dim"))
        console.print()
    s = report.summary
    counts = ", ".join(f"{s.findings[sev.value]} {sev.value}" for sev in reversed(Severity))
    console.print(
        Text(
            f"{s.targets} target(s), {s.unreachable} unreachable · {counts}"
            f" · fail-on {report.fail_on.value}",
            style="bold",
        )
    )
    return buf.getvalue()
