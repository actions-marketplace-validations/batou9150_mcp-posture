"""Report renderers. Every renderer returns text; :func:`render` applies redaction last."""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from typing import Literal

from mcp_posture.models import Report
from mcp_posture.redact import Redactor, redact_model
from mcp_posture.report import json as json_report
from mcp_posture.report import markdown, sarif, table

Format = Literal["table", "json", "sarif", "markdown"]
FORMATS: tuple[Format, ...] = ("table", "json", "sarif", "markdown")


def render(
    report: Report,
    fmt: Format,
    redactor: Redactor,
    *,
    color: bool = False,
    anchors: Mapping[str, sarif.Anchor] | None = None,
    default_anchor: sarif.Anchor = sarif.DEFAULT_ANCHOR,
) -> str:
    report = redact_model(report, redactor)  # field by field, before layout and truncation
    if fmt == "json":
        text = json_report.render(report)
    elif fmt == "sarif":
        text = sarif.render(report, anchors, default_anchor)
    elif fmt == "markdown":
        text = markdown.render(report)
    else:
        text = table.render(report, color=color)
    text = redactor.redact(text)
    if fmt == "table":
        return text  # table.render sanitizes each field itself, so rich's colors survive
    return neutralize(text, json_escapes=fmt in ("json", "sarif"))


def _invisible(c: str) -> bool:
    cat = unicodedata.category(c)
    return cat in ("Cf", "Co") or (cat == "Cc" and c not in "\n\t")


def neutralize(text: str, *, json_escapes: bool) -> str:
    """Server-controlled strings end up in reports: never emit raw control, bidi or
    invisible characters (terminal escape injection, Trojan Source). JSON gets standard
    ``\\uXXXX`` escapes; human formats get a visible ``<U+XXXX>`` marker."""
    out = []
    for c in text:
        if not _invisible(c):
            out.append(c)
        elif json_escapes:
            out.append("".join(f"\\u{u:04x}" for u in _utf16(c)))
        else:
            out.append(f"<U+{ord(c):04X}>")
    return "".join(out)


def _utf16(c: str) -> list[int]:
    raw = c.encode("utf-16-be")
    return [int.from_bytes(raw[i : i + 2], "big") for i in range(0, len(raw), 2)]
