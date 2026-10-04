"""Command-line interface."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import typer
from rich.console import Console

from mcp_posture import __version__
from mcp_posture.context import Target
from mcp_posture.engine import EXIT_USAGE, ScanOptions, exit_code, scan
from mcp_posture.models import Severity, SpecRevision
from mcp_posture.net import DEFAULT_USER_AGENT, NetSettings
from mcp_posture.redact import RedactingFilter, Redactor
from mcp_posture.registry import catalogue
from mcp_posture.report import FORMATS, Format, render

app = typer.Typer(
    name="mcp-posture",
    help="Security posture scanner for remote MCP servers. Only scan servers you own or are "
    "authorized to test.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)
checks_app = typer.Typer(help="Inspect the check catalogue.", no_args_is_help=True)
app.add_typer(checks_app, name="checks")

err = Console(stderr=True)


class UsageError(Exception):
    """Invalid input; maps to exit code 2."""


def _fail_usage(message: str) -> typer.Exit:
    err.print(f"[red]error:[/red] {message}")
    return typer.Exit(EXIT_USAGE)


def load_token(env: str | None, file: Path | None, stdin: bool) -> str | None:
    chosen = [x for x in (env, file, stdin or None) if x]
    if len(chosen) > 1:
        raise UsageError("use only one of --token-env, --token-file, --token-stdin")
    if env:
        value = os.environ.get(env)
        if not value:
            raise UsageError(f"environment variable {env} is empty or unset")
        return value.strip()
    if file:
        try:
            value = file.read_text(encoding="utf-8").strip()
        except OSError as e:
            raise UsageError(f"cannot read token file: {e.strerror}") from e
        if not value:
            raise UsageError("token file is empty")
        return value
    if stdin:
        value = sys.stdin.readline().strip()
        if not value:
            raise UsageError("no token on stdin")
        return value
    return None


def parse_targets(urls: list[str], targets_file: Path | None) -> list[Target]:
    raw: list[tuple[str, str]] = [(u, "cli") for u in urls]
    if targets_file is not None:
        try:
            lines = targets_file.read_text(encoding="utf-8").splitlines()
        except OSError as e:
            raise UsageError(f"cannot read targets file: {e.strerror}") from e
        for line in lines:
            line = line.split("#", 1)[0].strip()
            if line:
                raw.append((line, f"file:{targets_file}"))
    targets = []
    for url, source in raw:
        p = urlsplit(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise UsageError(f"not an http(s) URL: {url!r}")
        if p.username or p.password:
            raise UsageError("URLs must not embed credentials; use --token-env instead")
        targets.append(Target(url=url, source=source))
    if not targets:
        raise UsageError("no targets: pass URLs or --targets-file")
    return targets


def _selectors(values: list[str] | None) -> frozenset[str]:
    out: set[str] = set()
    for v in values or []:
        out.update(s.strip().upper() for s in v.split(",") if s.strip())
    return frozenset(out)


@app.command("scan")
def scan_cmd(
    urls: Annotated[list[str] | None, typer.Argument(help="MCP endpoint URL(s).")] = None,
    targets_file: Annotated[
        Path | None, typer.Option("--targets-file", help="File with one URL per line.")
    ] = None,
    fmt: Annotated[
        str, typer.Option("--format", "-f", help=f"Output format: {', '.join(FORMATS)}.")
    ] = "table",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the report to a file.")
    ] = None,
    fail_on: Annotated[
        Severity, typer.Option("--fail-on", help="Exit 1 when a finding is at least this severe.")
    ] = Severity.HIGH,
    spec: Annotated[
        str,
        typer.Option(
            "--spec", help="Pin the MCP spec revision (default: auto, from the handshake)."
        ),
    ] = "auto",
    token_env: Annotated[
        str | None, typer.Option("--token-env", help="Read a bearer token from this env var.")
    ] = None,
    token_file: Annotated[
        Path | None, typer.Option("--token-file", help="Read a bearer token from this file.")
    ] = None,
    token_stdin: Annotated[
        bool, typer.Option("--token-stdin", help="Read a bearer token from stdin.")
    ] = False,
    enable: Annotated[
        list[str] | None, typer.Option("--enable", help="Only run these check IDs/families.")
    ] = None,
    disable: Annotated[
        list[str] | None, typer.Option("--disable", help="Skip these check IDs/families.")
    ] = None,
    allow_private: Annotated[
        bool,
        typer.Option("--allow-private", help="Allow loopback/private/link-local addresses."),
    ] = False,
    ca_bundle: Annotated[
        Path | None, typer.Option("--ca-bundle", help="Custom CA bundle (PEM).")
    ] = None,
    proxy: Annotated[str | None, typer.Option("--proxy", help="HTTP(S) proxy URL.")] = None,
    timeout: Annotated[float, typer.Option("--timeout", help="Per-request timeout (s).")] = 10.0,
    retries: Annotated[int, typer.Option("--retries", help="Retries for idempotent requests.")] = 2,
    concurrency: Annotated[int, typer.Option("--concurrency", help="Targets in parallel.")] = 4,
    user_agent: Annotated[str, typer.Option("--user-agent")] = DEFAULT_USER_AGENT,
    no_tls_probe: Annotated[
        bool, typer.Option("--no-tls-probe", help="Skip the extra TLS handshakes.")
    ] = False,
    no_timestamp: Annotated[
        bool, typer.Option("--no-timestamp", help="Omit generated_at for reproducible output.")
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Scan one or more remote MCP servers (passive: metadata GETs + standard MCP handshake)."""
    try:
        if fmt not in FORMATS:
            raise UsageError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")
        pinned: SpecRevision | None = None
        if spec != "auto":
            pinned = SpecRevision.parse(spec)
            if pinned is None:
                known = ", ".join(r.value for r in SpecRevision)
                raise UsageError(f"unknown spec revision {spec!r}; known: auto, {known}")
        if ca_bundle is not None and not ca_bundle.is_file():
            raise UsageError(f"CA bundle not found: {ca_bundle}")
        if timeout <= 0 or retries < 0 or concurrency < 1:
            raise UsageError("timeout must be > 0, retries >= 0, concurrency >= 1")
        token = load_token(token_env, token_file, token_stdin)
        targets = parse_targets(urls or [], targets_file)
    except UsageError as e:
        raise _fail_usage(str(e)) from None

    redactor = Redactor([token] if token else [])
    _configure_logging(verbose, redactor)
    options = ScanOptions(
        net=NetSettings(
            timeout=timeout,
            retries=retries,
            proxy=proxy,
            ca_bundle=str(ca_bundle) if ca_bundle else None,
            user_agent=user_agent,
            allow_private=allow_private,
        ),
        spec=pinned,
        token=token,
        enable=_selectors(enable),
        disable=_selectors(disable),
        concurrency=concurrency,
        fail_on=fail_on,
        tls_probe=not no_tls_probe,
    )
    generated_at = None if no_timestamp else datetime.now(UTC).replace(microsecond=0)
    report = asyncio.run(scan(targets, options, generated_at=generated_at))
    format_: Format = "json" if fmt == "json" else "table"
    if output is not None:
        output.write_text(render(report, format_, redactor), encoding="utf-8")
    else:
        sys.stdout.write(render(report, format_, redactor, color=sys.stdout.isatty()))
    raise typer.Exit(exit_code(report))


def _configure_logging(verbose: bool, redactor: Redactor) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(RedactingFilter(redactor))
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger("mcp_posture")
    root.handlers[:] = [handler]
    root.setLevel(logging.DEBUG if verbose else logging.WARNING)
    root.propagate = False


@checks_app.command("list")
def checks_list() -> None:
    """List every check with its severity and applicable spec revisions."""
    from rich.table import Table

    table = Table(show_header=True, header_style="bold")
    for col in ("ID", "Severity", "Mode", "Revisions", "Title"):
        table.add_column(col)
    for meta in catalogue():
        revs = meta.revisions
        span = revs[0].value if len(revs) == 1 else f"{revs[0].value}+"
        if revs and revs[-1] != SpecRevision.latest():
            span = f"{revs[0].value}..{revs[-1].value}"
        table.add_row(meta.id, meta.severity.value, meta.mode, span, meta.title)
    Console().print(table)


@checks_app.command("show")
def checks_show(
    check_id: Annotated[str, typer.Argument(help="Check ID, e.g. MCPP-PRM03.")],
) -> None:
    """Show a check's rationale, remediation and references."""
    wanted = check_id.upper()
    meta = next((m for m in catalogue() if m.id == wanted), None)
    if meta is None:
        raise _fail_usage(f"unknown check {check_id!r}")
    out = Console()
    out.print(f"[bold]{meta.id}[/bold] {meta.title}")
    out.print(f"severity {meta.severity.value} · confidence {meta.confidence.value} · {meta.mode}")
    out.print(f"revisions: {', '.join(r.value for r in meta.revisions)}\n")
    out.print(f"[bold]Why[/bold]\n{meta.rationale}\n")
    out.print(f"[bold]Fix[/bold]\n{meta.remediation}\n")
    for ref in meta.references:
        out.print(f"- {ref.title}: {ref.url}")


@app.command("version")
def version_cmd() -> None:
    """Print the version."""
    typer.echo(__version__)


def main() -> None:
    app()
