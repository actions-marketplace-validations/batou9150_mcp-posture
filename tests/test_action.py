"""The composite GitHub Action: valid YAML, documented inputs, no script injection."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).parent.parent
UNSAFE_EXPANSION = re.compile(r"\$\{\{\s*(inputs|github\.event|github\.head_ref|env)\b")


def load(path: str) -> dict[str, Any]:
    data = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_action_metadata() -> None:
    action = load("action.yml")
    assert action["runs"]["using"] == "composite"
    for name, spec in action["inputs"].items():
        assert spec.get("description"), name
        assert "default" in spec or spec.get("required"), name
    assert {"exit-code", "sarif-file", "json-file"} <= set(action["outputs"])


def test_no_expression_expansion_inside_shell_scripts() -> None:
    """`${{ ... }}` inside `run:` is spliced into the shell source: inputs go through env."""
    workflows = [p.relative_to(ROOT).as_posix() for p in (ROOT / ".github/workflows").glob("*.yml")]
    for path in ["action.yml", *workflows]:
        doc = load(path)
        steps: list[dict[str, Any]] = list(doc.get("runs", {}).get("steps", []))
        for job in (doc.get("jobs") or {}).values():
            steps += job.get("steps", [])
        for step in steps:
            script = step.get("run", "")
            assert not UNSAFE_EXPANSION.search(script), (path, step.get("name"))


def test_workflows_parse_and_restrict_permissions() -> None:
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        doc = load(path.relative_to(ROOT).as_posix())
        assert "permissions" in doc, f"{path.name} must declare least-privilege permissions"
