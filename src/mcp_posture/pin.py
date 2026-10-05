"""Rug-pull pinning: a lock file of canonical hashes of every tool, prompt and resource."""

from __future__ import annotations

import difflib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

from mcp_posture import __version__
from mcp_posture.context import SurfaceItem
from mcp_posture.surface import canonical, canonical_json, item_hash

LOCK_VERSION = 1
DEFAULT_LOCK = "mcp-posture.lock.json"


class LockItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hash: str
    definition: dict[str, Any]


class Lock(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int = LOCK_VERSION
    generator: str = f"mcp-posture {__version__}"
    targets: dict[str, dict[str, LockItem]] = {}


class LockError(Exception):
    pass


def build_lock(surfaces: Mapping[str, Iterable[SurfaceItem]]) -> Lock:
    targets: dict[str, dict[str, LockItem]] = {}
    for url in sorted(surfaces):
        items = {
            i.location: LockItem(hash=item_hash(i), definition=canonical(i)) for i in surfaces[url]
        }
        targets[url] = dict(sorted(items.items()))
    return Lock(targets=targets)


def dump_lock(lock: Lock) -> str:
    return json.dumps(lock.model_dump(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def load_lock(path: Path) -> Lock:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as e:
        raise LockError(f"cannot read baseline {path}: {e.strerror}") from e
    except (ValueError, RecursionError) as e:
        raise LockError(f"baseline {path} is not valid JSON: {e}") from e
    try:
        lock = Lock.model_validate(raw)
    except ValidationError as e:
        raise LockError(f"baseline {path} is not a mcp-posture lock file: {e}") from e
    if lock.version != LOCK_VERSION:
        raise LockError(f"baseline {path} has version {lock.version}, expected {LOCK_VERSION}")
    return lock


@dataclass(frozen=True)
class Change:
    location: str
    fields: tuple[str, ...]
    diff: str


@dataclass(frozen=True)
class SurfaceDiff:
    added: tuple[str, ...]
    removed: tuple[str, ...]
    changed: tuple[Change, ...]

    @property
    def clean(self) -> bool:
        return not (self.added or self.removed or self.changed)


def diff_surface(pinned: Mapping[str, LockItem], current: Iterable[SurfaceItem]) -> SurfaceDiff:
    now = {i.location: i for i in current}
    added = tuple(sorted(set(now) - set(pinned)))
    removed = tuple(sorted(set(pinned) - set(now)))
    changed = []
    for loc in sorted(set(now) & set(pinned)):
        item = now[loc]
        if item_hash(item) == pinned[loc].hash:
            continue
        old, new = pinned[loc].definition, canonical(item)
        fields = tuple(sorted(k for k in set(old) | set(new) if old.get(k) != new.get(k)))
        changed.append(Change(loc, fields, unified_diff(old, new, loc)))
    return SurfaceDiff(added, removed, tuple(changed))


def unified_diff(old: Mapping[str, Any], new: Mapping[str, Any], name: str, limit: int = 60) -> str:
    a = canonical_json(old, pretty=True).splitlines()
    b = canonical_json(new, pretty=True).splitlines()
    label = json.dumps(name)  # server-controlled: one line, quoted
    lines = list(
        difflib.unified_diff(a, b, f"pinned {label}", f"current {label}", lineterm="", n=1)
    )
    if len(lines) > limit:
        lines = [*lines[:limit], f"... ({len(lines) - limit} more lines)"]
    return "\n".join(lines)
