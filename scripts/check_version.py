"""Fail unless a release tag matches every version string in the repo.

Usage: python scripts/check_version.py v1.2.3   (run from the repo root; needs `packaging`)
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

from packaging.version import InvalidVersion, Version

ROOT = Path(__file__).resolve().parent.parent


def versions() -> dict[str, str]:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    init = (ROOT / "src/mcp_posture/__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"', init, re.M)
    plugin = json.loads((ROOT / ".claude-plugin/plugin.json").read_text(encoding="utf-8"))
    manifest = json.loads((ROOT / ".release-please-manifest.json").read_text(encoding="utf-8"))
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    locked = next(p["version"] for p in lock["package"] if p["name"] == "mcp-posture")
    return {
        "pyproject.toml": pyproject["project"]["version"],
        "src/mcp_posture/__init__.py": match.group(1) if match else "",
        ".claude-plugin/plugin.json": plugin["version"],
        ".release-please-manifest.json": manifest["."],
        "uv.lock": locked,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 1 or not argv[0].startswith("v"):
        print("usage: check_version.py vX.Y.Z", file=sys.stderr)
        return 2
    try:
        expected = Version(argv[0][1:])
    except InvalidVersion:
        print(f"tag {argv[0]} is not a valid version", file=sys.stderr)
        return 1
    bad = []
    for where, value in versions().items():
        try:
            ok = Version(value) == expected
        except InvalidVersion:
            ok = False
        if not ok:
            bad.append(f"{where}: {value!r}")
    if bad:
        print(f"tag {argv[0]} does not match:\n  " + "\n  ".join(bad), file=sys.stderr)
        return 1
    print(f"{argv[0]}: all version strings match ({expected})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
