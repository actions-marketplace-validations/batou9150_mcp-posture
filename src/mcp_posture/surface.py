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
    """(field path, text) pairs a model reads: name, title, descriptions, argument docs.

    Server-controlled definitions may use any JSON type anywhere: nothing here assumes a
    shape, and schema text is collected at any depth (a nesting limit would be an evasion).
    """
    raw = thaw(item.definition)
    if not isinstance(raw, dict):
        return []
    out: list[tuple[str, str]] = []
    for key in ("name", "title", "description"):
        if isinstance(raw.get(key), str):
            out.append((key, raw[key]))
    arguments = raw.get("arguments")
    if isinstance(arguments, list):
        for i, arg in enumerate(arguments):
            if isinstance(arg, dict):
                for key in ("name", "title", "description"):
                    if isinstance(arg.get(key), str):
                        out.append((f"arguments[{i}].{key}", arg[key]))
    for key in ("inputSchema", "outputSchema"):
        _schema_texts(raw.get(key), key, out)
    return out


_TEXT_KEYS = frozenset({"description", "title", "default", "examples", "const", "enum"})


def _schema_texts(root: Any, root_path: str, out: list[tuple[str, str]]) -> None:
    """Every string a model may read in a JSON Schema: annotations, values, property names."""
    stack: list[tuple[Any, str, bool]] = [(root, root_path, False)]
    while stack:
        node, path, text_value = stack.pop()
        if isinstance(node, str):
            if text_value:
                out.append((path, node))
        elif isinstance(node, dict):
            names = path.endswith(".properties")  # keys are argument names, not keywords
            for k, v in reversed(list(node.items())):
                if names:
                    out.append((f"{path}[{k!r}]", str(k)))
                keyword = not names and k in _TEXT_KEYS
                stack.append((v, f"{path}.{k}", text_value or keyword))
        elif isinstance(node, list):
            for i in reversed(range(len(node))):
                stack.append((node[i], f"{path}[{i}]", text_value))
