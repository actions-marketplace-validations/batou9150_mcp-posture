"""Secret redaction. Every rendered output and every log record goes through a Redactor."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from enum import Enum
from typing import Any

from pydantic import BaseModel

MASK = "[REDACTED]"
# Any run of this many characters from a registered secret is masked: output layout and
# heuristics truncate, wrap or ellipsize strings, which would defeat an exact match.
FRAGMENT = 12

# JWT-shaped values (three base64url segments, the first one a JSON header).
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
# Authorization header values and bearer-ish query / form parameters.
# A token must contain a non-letter or be long, so prose like "Bearer challenge" survives.
_BEARER = re.compile(
    r"(?i)\b(bearer|dpop|basic)\s+"
    r"(?:(?=[A-Za-z0-9._~+/=-]*[0-9._~+/=-])[A-Za-z0-9._~+/=-]{8,}|[A-Za-z]{20,})"
)
_PARAMS = re.compile(
    r"(?i)\b(access_token|refresh_token|id_token|client_secret|code_verifier|api[_-]?key|password)"
    r"(\"?\s*[=:]\s*\"?)[^\s&\"',;]+"
)


class Redactor:
    """Masks registered secrets plus token-shaped strings."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        self._secrets: set[str] = set()
        self._fragments: set[str] = set()
        for s in secrets:
            self.add(s)

    def add(self, secret: str) -> None:
        secret = secret.strip()
        if len(secret) < 4:
            return
        # Also catch the JSON-escaped spelling, in case the secret is embedded in serialized output.
        for spelling in (secret, json.dumps(secret)[1:-1]):
            self._secrets.add(spelling)
            self._fragments.update(
                spelling[i : i + FRAGMENT] for i in range(len(spelling) - FRAGMENT + 1)
            )

    def _mask_fragments(self, text: str) -> str:
        if not self._fragments or len(text) < FRAGMENT:
            return text
        spans: list[list[int]] = []
        for i in range(len(text) - FRAGMENT + 1):
            if text[i : i + FRAGMENT] in self._fragments:
                if spans and i <= spans[-1][1]:
                    spans[-1][1] = i + FRAGMENT
                else:
                    spans.append([i, i + FRAGMENT])
        if not spans:
            return text
        out, last = [], 0
        for start, end in spans:
            out += [text[last:start], MASK]
            last = end
        out.append(text[last:])
        return "".join(out)

    def redact(self, text: str) -> str:
        for s in sorted(self._secrets, key=len, reverse=True):
            text = text.replace(s, MASK)
        text = self._mask_fragments(text)
        text = _JWT.sub(MASK, text)
        text = _BEARER.sub(lambda m: f"{m.group(1)} {MASK}", text)
        return _PARAMS.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}", text)


class RedactingFilter(logging.Filter):
    def __init__(self, redactor: Redactor) -> None:
        super().__init__()
        self._redactor = redactor

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._redactor.redact(record.getMessage())
        record.args = None
        return True


def redact_model[M: BaseModel](model: M, redactor: Redactor) -> M:
    """A copy of a (frozen) pydantic model with every string field redacted, recursively.

    Runs before any layout, so a secret is masked before it can be wrapped or truncated.
    """
    updates = {}
    for name in type(model).model_fields:
        value = getattr(model, name)
        new = _redact_value(value, redactor)
        if new is not value:
            updates[name] = new
    return model.model_copy(update=updates) if updates else model


def _redact_value(value: Any, redactor: Redactor) -> Any:
    if isinstance(value, Enum):
        return value
    if isinstance(value, str):
        new = redactor.redact(value)
        return value if new == value else new
    if isinstance(value, BaseModel):
        return redact_model(value, redactor)
    if isinstance(value, tuple):
        items = tuple(_redact_value(v, redactor) for v in value)
        return value if all(a is b for a, b in zip(items, value, strict=True)) else items
    return value
