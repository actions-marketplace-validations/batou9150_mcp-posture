"""Canonical form and hashing of the tool surface (tools, prompts, resources, templates).

Only security-relevant fields are hashed, so cosmetic server metadata (e.g. cache hints)
does not trigger rug-pull alerts. Unicode is deliberately *not* normalized: an invisible
character added to a description must change the hash.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from mcp_posture.context import SurfaceItem, thaw

HASHED_FIELDS = (
    "name",
    "title",
    "description",
    "inputSchema",
    "outputSchema",
    "annotations",
    "arguments",
    "uri",
    "uriTemplate",
    "mimeType",
)


def canonical(item: SurfaceItem) -> dict[str, Any]:
    raw = thaw(item.definition)
    return {k: raw[k] for k in HASHED_FIELDS if k in raw}


def canonical_json(data: Any, *, pretty: bool = False) -> str:
    if pretty:
        return json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False)
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def item_hash(item: SurfaceItem) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(canonical(item)).encode()).hexdigest()


def texts(item: SurfaceItem) -> list[tuple[str, str]]:
    """(field path, text) pairs a model reads: name, title, descriptions, argument docs."""
    raw = thaw(item.definition)
    out: list[tuple[str, str]] = []
    for key in ("name", "title", "description"):
        if isinstance(raw.get(key), str):
            out.append((key, raw[key]))
    for i, arg in enumerate(raw.get("arguments") or []):
        if isinstance(arg, dict):
            for key in ("name", "description"):
                if isinstance(arg.get(key), str):
                    out.append((f"arguments[{i}].{key}", arg[key]))
    for key in ("inputSchema", "outputSchema"):
        _schema_texts(raw.get(key), key, out)
    return out


def _schema_texts(node: Any, path: str, out: list[tuple[str, str]], depth: int = 0) -> None:
    if depth > 8:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            if k in ("description", "title", "default", "examples", "const") and isinstance(v, str):
                out.append((f"{path}.{k}", v))
            elif k == "enum" and isinstance(v, list):
                out.extend((f"{path}.enum", e) for e in v if isinstance(e, str))
            else:
                _schema_texts(v, f"{path}.{k}", out, depth + 1)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _schema_texts(v, f"{path}[{i}]", out, depth + 1)
