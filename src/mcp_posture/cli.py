"""Command-line interface."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import secrets
import stat
import sys
import webbrowser
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

import typer
from rich.console import Console
from rich.markup import escape

from mcp_posture import __version__
from mcp_posture.cimd_lint import LintInput, lint, parse_document
from mcp_posture.config import ConfigError, ScanConfig, build_config, load_config
from mcp_posture.context import Target
from mcp_posture.engine import (
    EXIT_UNREACHABLE,
    EXIT_USAGE,
    ScanOptions,
    collect_all,
    exit_code,
    scan,
)
from mcp_posture.login import (
    LoginError,
    LoginNotRequired,
    LoginOptions,
    LoginResult,
    LoginUI,
    login,
)
from mcp_posture.models import Report, Severity, SpecRevision, TargetResult, ToolInfo
from mcp_posture.net import Fetcher, HttpExchange, NetSettings
from mcp_posture.pin import (
    DEFAULT_LOCK,
    LockError,
    build_lock,
    dump_lock,
    duplicates,
    load_lock,
)
from mcp_posture.redact import RedactingFilter, Redactor
from mcp_posture.registry import catalogue
from mcp_posture.report import FORMATS, Format, neutralize, render
from mcp_posture.report.sarif import DEFAULT_ANCHOR, Anchor
from mcp_posture.sources import SourceError, discover, line_of, source_file
from mcp_posture.suppress import (
    DEFAULT_IGNORE_FILE,
    Suppression,
    SuppressionError,
    load_suppressions,
)

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
cimd_app = typer.Typer(help="Client ID Metadata Document tools.", no_args_is_help=True)
app.add_typer(cimd_app, name="cimd")

err = Console(stderr=True, soft_wrap=True)
CIMD_FETCH_LIMIT = 64 * 1024
EXIT_LOGIN_FAILED = 4


class UsageError(Exception):
    """Invalid input; maps to exit code 2."""


def _fail_usage(message: str) -> typer.Exit:
    err.print(f"[red]error:[/red] {message}", markup=True, highlight=False)
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


def _validate_url(url: str) -> None:
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise UsageError(f"not an http(s) URL: {url!r}")
    if p.username or p.password:
        raise UsageError("URLs must not embed credentials; use --token-env instead")


def gather_targets(cfg: ScanConfig, cli_urls: list[str], cwd: Path) -> list[Target]:
    targets = [Target(url=u, source="cli") for u in cli_urls]
    targets += [Target(url=u, source="config") for u in cfg.targets]
    if cfg.targets_file:
        path = Path(cfg.targets_file)
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as e:
            raise UsageError(f"cannot read targets file: {e.strerror}") from e
        for line in lines:
            line = line.split("#", 1)[0].strip()
            if line:
                targets.append(Target(url=line, source=f"file:{path}"))
    if cfg.client_configs:
        try:
            targets += discover(cfg.client_configs, cwd, Path.home())
        except SourceError as e:
            raise UsageError(str(e)) from e
    for t in targets:
        _validate_url(t.url)
    if not targets:
        raise UsageError("no targets: pass URLs, --targets-file or --from-client-config")
    return targets


def _selectors(values: list[str]) -> frozenset[str]:
    out: set[str] = set()
    for v in values:
        out.update(s.strip().upper() for s in v.split(",") if s.strip())
    return frozenset(out)


def _relative(path: Path, cwd: Path) -> str:
    try:
        return path.resolve().relative_to(cwd.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def sarif_anchors(
    targets: list[Target], cfg: ScanConfig, config_path: Path | None, cwd: Path
) -> tuple[dict[str, Anchor], Anchor]:
    """Anchor each target to the file (and line) that declares it, for code scanning."""
    default = DEFAULT_ANCHOR
    if cfg.sarif_anchor:
        default = (cfg.sarif_anchor, 1)
    elif config_path is not None:
        default = (_relative(config_path, cwd), 1)
    anchors: dict[str, Anchor] = {}
    for t in targets:
        path = source_file(t)
        if path is None and t.source == "config" and config_path is not None:
            path = config_path
        if path is not None:
            anchors.setdefault(t.url, (_relative(path, cwd), line_of(path, t.url)))
    return anchors, default


def _options(cfg: ScanConfig, token: str | None, **extra: Any) -> ScanOptions:
    return ScanOptions(
        net=NetSettings(
            timeout=cfg.timeout,
            retries=cfg.retries,
            backoff=cfg.backoff,
            max_bytes=cfg.max_bytes,
            proxy=cfg.proxy,
            ca_bundle=cfg.ca_bundle,
            user_agent=cfg.user_agent,
            allow_private=cfg.allow_private,
        ),
        spec=cfg.pinned_spec,
        token=token,
        enable=_selectors(cfg.enable),
        disable=_selectors(cfg.disable),
        concurrency=cfg.concurrency,
        target_timeout=cfg.target_timeout,
        fail_on=cfg.fail_on,
        tls_probe=cfg.tls_probe,
        **extra,
    )


def _configure_logging(verbose: bool, redactor: Redactor) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(RedactingFilter(redactor))
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger("mcp_posture")
    root.handlers[:] = [handler]
    root.setLevel(logging.DEBUG if verbose else logging.WARNING)
    root.propagate = False


def _login_options(
    cfg: ScanConfig,
    *,
    client_id: str | None,
    client_secret_env: str | None,
    client_metadata_url: str | None,
    register: bool | None,
    keep_client: bool,
    scope: str | None,
    port: int | None,
    no_browser: bool,
    login_timeout: float | None,
    authorization_server: str | None,
) -> LoginOptions:
    """[login] from the config file, overridden by explicit CLI values."""
    base = cfg.login
    secret = None
    if client_secret_env:
        secret = os.environ.get(client_secret_env)
        if not secret:
            raise UsageError(f"environment variable {client_secret_env} is empty or unset")
    return LoginOptions(
        client_id=client_id or base.client_id,
        client_secret=secret,
        client_metadata_url=client_metadata_url or base.client_metadata_url,
        register=register if register is not None else base.allow_registration,
        keep_client=keep_client or base.keep_client,
        scope=scope or base.scope,
        port=port if port is not None else base.port,
        open_browser=not no_browser,
        timeout=login_timeout or base.timeout,
        authorization_server=authorization_server or base.authorization_server,
    )


def _safe(text: str, redactor: Redactor) -> str:
    """Server-influenced text for the terminal: secrets masked, no control/escape sequences
    (rich passes ESC through even with markup off), no rich markup."""
    return escape(neutralize(redactor.redact(text), json_escapes=False))


def _ui(redactor: Redactor) -> LoginUI:
    def say(message: str) -> None:
        err.print(_safe(message, redactor), highlight=False)

    def confirm(question: str) -> bool:
        return typer.confirm(question, default=False, err=True)

    interactive = sys.stdin.isatty()
    return LoginUI(say=say, open_url=webbrowser.open, confirm=confirm if interactive else None)


def run_login(url: str, opts: LoginOptions, net: NetSettings, redactor: Redactor) -> LoginResult:
    return asyncio.run(login(url, opts, net, _ui(redactor), redactor=redactor))


def _stdout_is_tty() -> bool:
    return sys.stdout.isatty()


def write_token_file(path: Path, token: str) -> None:
    """Write ``token`` readable by the owner only; never through a symlink."""
    data = (token + "\n").encode()
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
        except OSError as e:
            raise UsageError(f"cannot create {path}: {e.strerror}") from e
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        except OSError as e:
            with contextlib.suppress(OSError):
                path.unlink()
            raise UsageError(f"cannot write {path}: {e.strerror}") from e
        return
    if not stat.S_ISREG(st.st_mode):
        raise UsageError(f"{path} is not a regular file (symlinks are refused)")
    if st.st_mode & 0o077 or (hasattr(os, "getuid") and st.st_uid != os.getuid()):
        mode = stat.S_IMODE(st.st_mode)
        raise UsageError(f"{path} already exists with mode {mode:o}; it must be 600 and yours")
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except OSError as e:
        with contextlib.suppress(OSError):
            tmp.unlink()  # never leave a stray copy of the token behind
        raise UsageError(f"cannot write {path}: {e.strerror}") from e


def _report_login(result: LoginResult, redactor: Redactor) -> None:
    for w in result.warnings:
        err.print(f"[yellow]warning:[/yellow] {_safe(w, redactor)}", highlight=False)
    err.print(
        f"Logged in to {_safe(result.issuer, redactor)} (client: {result.strategy}"
        + (f", scope: {_safe(result.scope, redactor)}" if result.scope else "")
        + "). The token is not shown.",
        highlight=False,
    )


ConfigOpt = Annotated[
    Path | None, typer.Option("--config", help="Config file (default: ./mcp-posture.toml).")
]
TargetsFileOpt = Annotated[
    Path | None, typer.Option("--targets-file", help="File with one URL per line.")
]
ClientConfigOpt = Annotated[
    list[str] | None,
    typer.Option(
        "--from-client-config",
        help="Scan remote servers declared in MCP client configs: a path, or 'auto' for "
        ".mcp.json, Claude Desktop/Code, VS Code, Cursor, Windsurf.",
    ),
]
TokenEnvOpt = Annotated[
    str | None, typer.Option("--token-env", help="Read a bearer token from this env var.")
]
TokenFileOpt = Annotated[
    Path | None, typer.Option("--token-file", help="Read a bearer token from this file.")
]
TokenStdinOpt = Annotated[
    bool, typer.Option("--token-stdin", help="Read a bearer token from stdin.")
]
AllowPrivateOpt = Annotated[
    bool, typer.Option("--allow-private", help="Allow loopback/private/link-local addresses.")
]
LOGIN_PANEL = "Login (OAuth to a server you own)"
ClientIdOpt = Annotated[
    str | None,
    typer.Option("--client-id", help="Pre-registered client ID.", rich_help_panel=LOGIN_PANEL),
]
ClientSecretEnvOpt = Annotated[
    str | None,
    typer.Option(
        "--client-secret-env",
        help="Env var holding the secret of a pre-registered confidential client.",
        rich_help_panel=LOGIN_PANEL,
    ),
]
ClientMetadataUrlOpt = Annotated[
    str | None,
    typer.Option(
        "--client-metadata-url",
        help="HTTPS URL of your Client ID Metadata Document (CIMD).",
        rich_help_panel=LOGIN_PANEL,
    ),
]
RegisterOpt = Annotated[
    bool | None,
    typer.Option(
        "--register/--no-register",
        help="Allow Dynamic Client Registration (creates a client on the AS). Asks if unset.",
        rich_help_panel=LOGIN_PANEL,
    ),
]
KeepClientOpt = Annotated[
    bool,
    typer.Option(
        "--keep-client", help="Keep a DCR-registered client.", rich_help_panel=LOGIN_PANEL
    ),
]
ScopeOpt = Annotated[
    str | None,
    typer.Option(
        "--scope", help="Scopes to request (space-separated).", rich_help_panel=LOGIN_PANEL
    ),
]
PortOpt = Annotated[
    int | None,
    typer.Option(
        "--port",
        min=0,
        max=65535,
        help="Loopback port for the redirect [ephemeral].",
        rich_help_panel=LOGIN_PANEL,
    ),
]
NoBrowserOpt = Annotated[
    bool,
    typer.Option(
        "--no-browser", help="Print the authorization URL instead.", rich_help_panel=LOGIN_PANEL
    ),
]
LoginTimeoutOpt = Annotated[
    float | None,
    typer.Option(
        "--login-timeout",
        help="Seconds to wait for the redirect [300].",
        rich_help_panel=LOGIN_PANEL,
    ),
]
AuthServerOpt = Annotated[
    str | None,
    typer.Option(
        "--authorization-server",
        help="Which authorization server, when PRM lists several.",
        rich_help_panel=LOGIN_PANEL,
    ),
]


def _resolve(
    config: Path | None,
    cli_values: dict[str, Any],
    urls: list[str],
    token_env: str | None,
    token_file: Path | None,
    token_stdin: bool,
) -> tuple[ScanConfig, Path | None, list[Target], str | None]:
    cwd = Path.cwd()
    try:
        file_values, config_path = load_config(config, cwd)
        cfg = build_config(file_values, cli_values, str(config_path or "command line"))
        if cfg.ca_bundle is not None and not Path(cfg.ca_bundle).is_file():
            raise UsageError(f"CA bundle not found: {cfg.ca_bundle}")
        token = load_token(token_env, token_file, token_stdin)
        targets = gather_targets(cfg, urls, cwd)
    except (ConfigError, UsageError) as e:
        raise _fail_usage(str(e)) from None
    return cfg, config_path, targets, token


@app.command("scan")
def scan_cmd(
    urls: Annotated[list[str] | None, typer.Argument(help="MCP endpoint URL(s).")] = None,
    config: ConfigOpt = None,
    targets_file: TargetsFileOpt = None,
    client_config: ClientConfigOpt = None,
    fmt: Annotated[
        str, typer.Option("--format", "-f", help=f"stdout format: {', '.join(FORMATS)}.")
    ] = "table",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the --format report to a file.")
    ] = None,
    json_out: Annotated[Path | None, typer.Option("--json", help="Also write JSON here.")] = None,
    sarif_out: Annotated[
        Path | None, typer.Option("--sarif", help="Also write SARIF 2.1.0 here.")
    ] = None,
    markdown_out: Annotated[
        Path | None, typer.Option("--markdown", help="Also write a Markdown summary here.")
    ] = None,
    sarif_anchor: Annotated[
        str | None,
        typer.Option("--sarif-anchor", help="Repo file that SARIF results point to by default."),
    ] = None,
    fail_on: Annotated[
        Severity | None,
        typer.Option("--fail-on", help="Exit 1 when a finding is at least this severe [high]."),
    ] = None,
    spec: Annotated[
        str | None,
        typer.Option("--spec", help="Pin the MCP spec revision (default: auto, from handshake)."),
    ] = None,
    baseline: Annotated[
        Path | None,
        typer.Option("--baseline", help=f"Lock file from `mcp-posture pin` ({DEFAULT_LOCK})."),
    ] = None,
    ignore_file: Annotated[
        Path | None,
        typer.Option(
            "--ignore-file", help=f"Suppressions file (default: ./{DEFAULT_IGNORE_FILE})."
        ),
    ] = None,
    token_env: TokenEnvOpt = None,
    token_file: TokenFileOpt = None,
    token_stdin: TokenStdinOpt = False,
    enable: Annotated[
        list[str] | None, typer.Option("--enable", help="Only run these check IDs/families.")
    ] = None,
    disable: Annotated[
        list[str] | None, typer.Option("--disable", help="Skip these check IDs/families.")
    ] = None,
    allow_private: AllowPrivateOpt = False,
    ca_bundle: Annotated[
        Path | None, typer.Option("--ca-bundle", help="Custom CA bundle (PEM).")
    ] = None,
    proxy: Annotated[str | None, typer.Option("--proxy", help="HTTP(S) proxy URL.")] = None,
    timeout: Annotated[
        float | None, typer.Option("--timeout", help="Per-request timeout in s [10].")
    ] = None,
    target_timeout: Annotated[
        float | None,
        typer.Option("--target-timeout", help="Overall time limit per target in s [300]."),
    ] = None,
    retries: Annotated[
        int | None, typer.Option("--retries", help="Retries for idempotent requests [2].")
    ] = None,
    concurrency: Annotated[
        int | None, typer.Option("--concurrency", help="Targets in parallel [4].")
    ] = None,
    user_agent: Annotated[str | None, typer.Option("--user-agent")] = None,
    no_tls_probe: Annotated[
        bool, typer.Option("--no-tls-probe", help="Skip the extra TLS handshakes.")
    ] = False,
    no_timestamp: Annotated[
        bool, typer.Option("--no-timestamp", help="Omit generated_at for reproducible output.")
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
    do_login: Annotated[
        bool,
        typer.Option(
            "--login",
            help="Log in first (browser, OAuth + PKCE) and scan with that token; one target.",
            rich_help_panel=LOGIN_PANEL,
        ),
    ] = False,
    client_id: ClientIdOpt = None,
    client_secret_env: ClientSecretEnvOpt = None,
    client_metadata_url: ClientMetadataUrlOpt = None,
    register: RegisterOpt = None,
    keep_client: KeepClientOpt = False,
    scope: ScopeOpt = None,
    port: PortOpt = None,
    no_browser: NoBrowserOpt = False,
    login_timeout: LoginTimeoutOpt = None,
    authorization_server: AuthServerOpt = None,
) -> None:
    """Scan remote MCP servers (passive: metadata GETs + standard MCP handshake)."""
    if fmt not in FORMATS:
        raise _fail_usage(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")
    cli_values: dict[str, Any] = {
        "targets_file": str(targets_file) if targets_file else None,
        "client_configs": client_config,
        "fail_on": fail_on,
        "spec": spec,
        "enable": enable,
        "disable": disable,
        "timeout": timeout,
        "target_timeout": target_timeout,
        "retries": retries,
        "concurrency": concurrency,
        "proxy": proxy,
        "ca_bundle": str(ca_bundle) if ca_bundle else None,
        "user_agent": user_agent,
        "allow_private": True if allow_private else None,
        "tls_probe": False if no_tls_probe else None,
        "baseline": str(baseline) if baseline else None,
        "ignore_file": str(ignore_file) if ignore_file else None,
        "sarif_anchor": sarif_anchor,
    }
    cfg, config_path, targets, token = _resolve(
        config, cli_values, urls or [], token_env, token_file, token_stdin
    )
    try:
        lock = load_lock(Path(cfg.baseline)) if cfg.baseline else None
        suppressions = _load_ignore(cfg)
    except (LockError, SuppressionError) as e:
        raise _fail_usage(str(e)) from None

    redactor = Redactor([token] if token else [])
    _configure_logging(verbose, redactor)
    if do_login:
        if token is not None:
            raise _fail_usage("--login and --token-env/--token-file/--token-stdin are exclusive")
        if len(targets) != 1:
            raise _fail_usage("--login scans exactly one target")
        try:
            login_opts = _login_options(
                cfg,
                client_id=client_id,
                client_secret_env=client_secret_env,
                client_metadata_url=client_metadata_url,
                register=register,
                keep_client=keep_client,
                scope=scope,
                port=port,
                no_browser=no_browser,
                login_timeout=login_timeout,
                authorization_server=authorization_server,
            )
        except UsageError as e:
            raise _fail_usage(str(e)) from None
        try:
            result = run_login(targets[0].url, login_opts, _options(cfg, None).net, redactor)
        except LoginNotRequired:
            err.print("This server does not require authentication; scanning without a token.")
        except LoginError as e:
            err.print(f"[red]login failed:[/red] {_safe(str(e), redactor)}", highlight=False)
            raise typer.Exit(EXIT_UNREACHABLE if e.unreachable else EXIT_LOGIN_FAILED) from None
        else:
            _report_login(result, redactor)
            token = result.access_token
            redactor.add(token)
    options = _options(cfg, token, baseline=lock, suppressions=tuple(suppressions))
    generated_at = None if no_timestamp else datetime.now(UTC).replace(microsecond=0)
    report = asyncio.run(scan(targets, options, generated_at=generated_at))

    anchors, default_anchor = sarif_anchors(targets, cfg, config_path, Path.cwd())

    def out(kind: Format, color: bool = False) -> str:
        return render(
            report, kind, redactor, color=color, anchors=anchors, default_anchor=default_anchor
        )

    sinks: tuple[tuple[Path | None, Format], ...] = (
        (json_out, "json"),
        (sarif_out, "sarif"),
        (markdown_out, "markdown"),
    )
    for path, kind in sinks:
        if path is not None:
            path.write_text(out(kind), encoding="utf-8")
    format_: Format = fmt
    if output is not None:
        output.write_text(out(format_), encoding="utf-8")
    else:
        sys.stdout.write(out(format_, color=sys.stdout.isatty()))
    raise typer.Exit(exit_code(report))


def _load_ignore(cfg: ScanConfig) -> list[Suppression]:
    if cfg.ignore_file:
        return load_suppressions(Path(cfg.ignore_file))
    default = Path.cwd() / DEFAULT_IGNORE_FILE
    return load_suppressions(default) if default.is_file() else []


@app.command("pin")
def pin_cmd(
    urls: Annotated[list[str] | None, typer.Argument(help="MCP endpoint URL(s).")] = None,
    output: Annotated[Path, typer.Option("--output", "-o", help="Lock file to write.")] = Path(
        DEFAULT_LOCK
    ),
    config: ConfigOpt = None,
    targets_file: TargetsFileOpt = None,
    client_config: ClientConfigOpt = None,
    token_env: TokenEnvOpt = None,
    token_file: TokenFileOpt = None,
    token_stdin: TokenStdinOpt = False,
    allow_private: AllowPrivateOpt = False,
) -> None:
    """Record canonical hashes of every tool, prompt and resource (rug-pull baseline)."""
    cli_values: dict[str, Any] = {
        "targets_file": str(targets_file) if targets_file else None,
        "client_configs": client_config,
        "allow_private": True if allow_private else None,
        "tls_probe": False,
    }
    cfg, _, targets, token = _resolve(
        config, cli_values, urls or [], token_env, token_file, token_stdin
    )
    redactor = Redactor([token] if token else [])
    _configure_logging(False, redactor)
    collected = asyncio.run(collect_all(targets, _options(cfg, token)))
    surfaces = {}
    failed = 0
    for c in collected:
        if c.ctx is None:
            err.print(f"[red]unreachable[/red] {c.target.url}: {c.error}", highlight=False)
            failed += 1
        elif not c.ctx.mcp.surface_listed:
            err.print(
                f"[yellow]skipped[/yellow] {c.target.url}: tool surface not listable"
                + (" (authentication required; pass a token)" if c.ctx.mcp.auth_required else ""),
                highlight=False,
            )
            failed += 1
        else:
            surfaces[c.target.url] = c.ctx.mcp.surface
            err.print(f"[green]pinned[/green] {c.target.url}: {len(c.ctx.mcp.surface)} item(s)")
            for loc in duplicates(c.ctx.mcp.surface):
                err.print(
                    f"[yellow]warning[/yellow] {c.target.url}: {_safe(loc, redactor)} is listed"
                    " with several definitions; only the first one is pinned, review the others",
                    highlight=False,
                )
    if surfaces:
        output.write_text(dump_lock(build_lock(surfaces)), encoding="utf-8")
        err.print(f"wrote {output}")
    raise typer.Exit(3 if failed else 0)


@app.command("discover")
def discover_cmd(
    client_config: Annotated[
        list[str] | None,
        typer.Argument(help="Config paths, or 'auto' (default) for known MCP client configs."),
    ] = None,
) -> None:
    """List remote MCP servers declared in MCP client configs (never prints headers or env)."""
    try:
        targets = discover(client_config or ["auto"], Path.cwd(), Path.home())
    except SourceError as e:
        raise _fail_usage(str(e)) from None
    for t in targets:
        typer.echo(f"{t.url}\t{t.name}\t{t.source.removeprefix('config:')}")
    if not targets:
        err.print("no remote MCP servers found")


async def _fetch_cimd(url: str, settings: NetSettings) -> HttpExchange:
    async with Fetcher(settings) as fetcher:
        return await fetcher.request(
            "GET",
            url,
            headers={"Accept": "application/json"},
            follow_redirects=False,  # authorization servers MUST NOT follow redirects
            max_bytes=CIMD_FETCH_LIMIT,
        )


@cimd_app.command("lint")
def cimd_lint_cmd(
    source: Annotated[str, typer.Argument(help="Document URL (https://...) or local file.")],
    url: Annotated[
        str | None,
        typer.Option("--url", help="For a local file: the URL it will be served at."),
    ] = None,
    fmt: Annotated[
        str, typer.Option("--format", "-f", help=f"Output format: {', '.join(FORMATS)}.")
    ] = "table",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    fail_on: Annotated[Severity, typer.Option("--fail-on")] = Severity.HIGH,
    allow_private: AllowPrivateOpt = False,
    ca_bundle: Annotated[Path | None, typer.Option("--ca-bundle")] = None,
) -> None:
    """Validate a client's Client ID Metadata Document (draft-02 + MCP requirements)."""
    if fmt not in FORMATS:
        raise _fail_usage(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")
    exchange: HttpExchange | None = None
    if source.startswith(("https://", "http://")):
        settings = NetSettings(
            retries=0,
            allow_private=allow_private,
            ca_bundle=str(ca_bundle) if ca_bundle else None,
        )
        exchange = asyncio.run(_fetch_cimd(source, settings))
        raw = exchange.body
        client_id_url: str | None = source
    else:
        try:
            raw = Path(source).read_bytes()
        except OSError as e:
            raise _fail_usage(f"cannot read {source}: {e.strerror}") from None
        client_id_url = url
    document, parse_error = parse_document(raw) if raw else (None, "empty document")
    if client_id_url is None and document is not None:
        cid = document.get("client_id")
        client_id_url = cid if isinstance(cid, str) else None
    reachable = exchange is None or exchange.status is not None
    findings = (
        lint(
            LintInput(
                source=source,
                document=document,
                client_id_url=client_id_url,
                exchange=exchange,
                raw_size=len(raw),
                parse_error=parse_error,
            )
        )
        if reachable
        else []
    )
    result = TargetResult(
        target=source,
        source="cimd-lint",
        reachable=reachable,
        error=exchange.error if exchange is not None and not reachable else None,
        spec_revision=SpecRevision.latest(),
        revision_source="default",
        findings=tuple(findings),
    )
    report = Report(
        tool=ToolInfo(version=__version__),
        generated_at=None,
        mode="lint",
        fail_on=fail_on,
        targets=(result,),
    )
    format_: Format = fmt
    text = render(report, format_, Redactor(), color=output is None and sys.stdout.isatty())
    if output is not None:
        output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    raise typer.Exit(exit_code(report))


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
    if not wanted.startswith("MCPP-"):
        wanted = f"MCPP-{wanted}"
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


@app.command("login")
def login_cmd(
    url: Annotated[str, typer.Argument(help="MCP endpoint URL (a server you own).")],
    token_file: Annotated[
        Path | None,
        typer.Option("--token-file", help="Write the access token here (mode 600)."),
    ] = None,
    show_token: Annotated[
        bool, typer.Option("--show-token", help="Allow printing the token to a terminal.")
    ] = False,
    config: ConfigOpt = None,
    client_id: ClientIdOpt = None,
    client_secret_env: ClientSecretEnvOpt = None,
    client_metadata_url: ClientMetadataUrlOpt = None,
    register: RegisterOpt = None,
    keep_client: KeepClientOpt = False,
    scope: ScopeOpt = None,
    port: PortOpt = None,
    no_browser: NoBrowserOpt = False,
    login_timeout: LoginTimeoutOpt = None,
    authorization_server: AuthServerOpt = None,
    allow_private: AllowPrivateOpt = False,
    ca_bundle: Annotated[
        Path | None, typer.Option("--ca-bundle", help="Custom CA bundle (PEM).")
    ] = None,
    proxy: Annotated[str | None, typer.Option("--proxy", help="HTTP(S) proxy URL.")] = None,
    timeout: Annotated[
        float | None, typer.Option("--timeout", help="Per-request timeout in s [10].")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Log in to an MCP server you own (OAuth code flow + PKCE) and output an access token.

    The token goes to stdout only when it is captured, e.g.
    export MCP_TOKEN="$(mcp-posture login URL)", or to --token-file.
    """
    if token_file is None and not show_token and _stdout_is_tty():
        raise _fail_usage(
            "refusing to print a token to the terminal. Capture it instead: "
            'export MCP_TOKEN="$(mcp-posture login URL)", or use --token-file PATH '
            "(or --show-token)"
        )
    cli_values: dict[str, Any] = {
        "allow_private": True if allow_private else None,
        "ca_bundle": str(ca_bundle) if ca_bundle else None,
        "proxy": proxy,
        "timeout": timeout,
        "tls_probe": False,
    }
    cfg, _, _targets, _ = _resolve(config, cli_values, [url], None, None, False)
    try:
        opts = _login_options(
            cfg,
            client_id=client_id,
            client_secret_env=client_secret_env,
            client_metadata_url=client_metadata_url,
            register=register,
            keep_client=keep_client,
            scope=scope,
            port=port,
            no_browser=no_browser,
            login_timeout=login_timeout,
            authorization_server=authorization_server,
        )
    except UsageError as e:
        raise _fail_usage(str(e)) from None
    redactor = Redactor()
    _configure_logging(verbose, redactor)
    try:
        result = run_login(url, opts, _options(cfg, None).net, redactor)
    except LoginNotRequired:
        err.print("This server does not require authentication; no token needed.")
        raise typer.Exit(0) from None
    except LoginError as e:
        err.print(f"[red]login failed:[/red] {_safe(str(e), redactor)}", highlight=False)
        raise typer.Exit(EXIT_UNREACHABLE if e.unreachable else 1) from None
    _report_login(result, redactor)
    if token_file is not None:
        try:
            write_token_file(token_file, result.access_token)
        except UsageError as e:
            raise _fail_usage(str(e)) from None
        err.print(f"Token written to {token_file}.", highlight=False)
    else:
        sys.stdout.write(result.access_token + "\n")


@app.command("version")
def version_cmd() -> None:
    """Print the version."""
    typer.echo(__version__)


def main() -> None:
    app(prog_name="mcp-posture")
