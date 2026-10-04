"""Report renderers. Every renderer returns text; :func:`render` applies redaction last."""

from __future__ import annotations

from typing import Literal

from mcp_posture.models import Report
from mcp_posture.redact import Redactor
from mcp_posture.report import json as json_report
from mcp_posture.report import table

Format = Literal["table", "json"]
FORMATS: tuple[Format, ...] = ("table", "json")


def render(report: Report, fmt: Format, redactor: Redactor, *, color: bool = False) -> str:
    text = json_report.render(report) if fmt == "json" else table.render(report, color=color)
    return redactor.redact(text)
