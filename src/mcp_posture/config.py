"""``mcp-posture.toml`` configuration. Precedence: CLI flags > config file > defaults.

[scan]
targets = ["https://mcp.example.com/mcp"]
fail_on = "high"
spec = "auto"
disable = ["ASM08"]
timeout = 10
retries = 2
ca_bundle = "certs/internal-ca.pem"   # relative paths resolve from this file's directory
baseline = "mcp-posture.lock.json"
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from mcp_posture.models import Severity, SpecRevision
from mcp_posture.net import DEFAULT_USER_AGENT

DEFAULT_CONFIG = "mcp-posture.toml"
PATH_FIELDS = ("ca_bundle", "baseline", "ignore_file", "targets_file")


class ConfigError(Exception):
    pass


class LoginConfig(BaseModel):
    """``[login]`` in mcp-posture.toml. Secrets are never read from the config file."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    client_id: str | None = None
    client_metadata_url: str | None = None
    authorization_server: str | None = None
    scope: str | None = None
    port: int = Field(0, ge=0, le=65535)
    allow_registration: bool | None = Field(None, alias="register")  # TOML key: register
    keep_client: bool = False
    timeout: float = Field(300.0, gt=0, le=3600)


class ScanConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    targets: list[str] = []
    targets_file: str | None = None
    client_configs: list[str] = []
    fail_on: Severity = Severity.HIGH
    spec: str = "auto"
    enable: list[str] = []
    disable: list[str] = []
    timeout: float = Field(10.0, gt=0, le=300)
    target_timeout: float = Field(300.0, gt=0, le=3600)
    retries: int = Field(2, ge=0, le=10)
    backoff: float = Field(0.5, ge=0, le=30)
    max_bytes: int = Field(1_048_576, ge=1024, le=64 * 1_048_576)
    concurrency: int = Field(4, ge=1, le=64)
    proxy: str | None = None
    ca_bundle: str | None = None
    user_agent: str = DEFAULT_USER_AGENT
    allow_private: bool = False
    tls_probe: bool = True
    baseline: str | None = None
    ignore_file: str | None = None
    sarif_anchor: str | None = None
    login: LoginConfig = LoginConfig()

    @field_validator("spec")
    @classmethod
    def _spec(cls, v: str) -> str:
        if v != "auto" and SpecRevision.parse(v) is None:
            known = ", ".join(r.value for r in SpecRevision)
            raise ValueError(f"unknown spec revision {v!r}; known: auto, {known}")
        return v

    @property
    def pinned_spec(self) -> SpecRevision | None:
        return None if self.spec == "auto" else SpecRevision.parse(self.spec)


class _File(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan: dict[str, Any] = {}
    login: dict[str, Any] = {}


def _format(e: ValidationError, source: str) -> str:
    parts = [f"{'.'.join(str(x) for x in err['loc'])}: {err['msg']}" for err in e.errors()]
    return f"{source}: " + "; ".join(parts)


def load_config(path: Path | None, cwd: Path) -> tuple[dict[str, Any], Path | None]:
    """Raw ``[scan]`` values from the file (paths resolved), and the file used."""
    if path is None:
        candidate = cwd / DEFAULT_CONFIG
        if not candidate.is_file():
            return {}, None
        path = candidate
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise ConfigError(f"cannot read {path}: {e.strerror}") from e
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: invalid TOML: {e}") from e
    try:
        parsed = _File.model_validate(data)
    except ValidationError as e:
        raise ConfigError(_format(e, str(path))) from e
    raw = dict(parsed.scan)
    if parsed.login:
        raw["login"] = parsed.login
    base = path.parent
    for key in PATH_FIELDS:
        if isinstance(raw.get(key), str):
            raw[key] = (
                str((base / raw[key]).resolve()) if not Path(raw[key]).is_absolute() else raw[key]
            )
    return raw, path


def build_config(
    file_values: dict[str, Any], cli_values: dict[str, Any], source: str
) -> ScanConfig:
    """Merge: CLI values that were explicitly given (not None) override the file."""
    merged = {**file_values, **{k: v for k, v in cli_values.items() if v is not None}}
    try:
        return ScanConfig.model_validate(merged)
    except ValidationError as e:
        raise ConfigError(_format(e, source)) from e
