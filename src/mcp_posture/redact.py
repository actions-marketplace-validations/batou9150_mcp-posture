"""Secret redaction. Every rendered output and every log record goes through a Redactor."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable

MASK = "[REDACTED]"

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
        for s in secrets:
            self.add(s)

    def add(self, secret: str) -> None:
        secret = secret.strip()
        if len(secret) < 4:
            return
        self._secrets.add(secret)
        # Also catch the JSON-escaped spelling, in case the secret is embedded in serialized output.
        self._secrets.add(json.dumps(secret)[1:-1])

    def redact(self, text: str) -> str:
        for s in sorted(self._secrets, key=len, reverse=True):
            text = text.replace(s, MASK)
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
