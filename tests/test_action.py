"""The composite GitHub Action: valid YAML, documented inputs, no script injection."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).parent.parent
# These tests inspect repository files (action, workflows, Dockerfile) not shipped in the sdist.
pytestmark = pytest.mark.skipif(
    not (ROOT / "action.yml").is_file(), reason="needs a repository checkout"
)
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


def test_scan_step_reports_exit_code_under_errexit(tmp_path: Path) -> None:
    """GitHub runs `shell: bash` as `bash -e`: findings (exit 1) must not abort the step."""
    step = next(s for s in load("action.yml")["runs"]["steps"] if s.get("id") == "scan")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "uv"
    argv = tmp_path / "argv"
    fake.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{argv}"\nexit 1\n', encoding="utf-8")
    fake.chmod(0o755)
    script = tmp_path / "step.sh"
    script.write_text(step["run"], encoding="utf-8")
    output = tmp_path / "github_output"
    env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "GITHUB_OUTPUT": str(output),
        "MCPP_OUT": str(tmp_path / "out"),
        "MCPP_SOURCE": str(ROOT),
        "MCPP_FAIL_ON": "high",
        "MCPP_TARGETS": "  https://mcp.example.com/mcp  # prod\n--token-file /etc/passwd\nit's\n",
        **{k: "" for k in ("MCPP_CONFIG", "MCPP_TARGETS_FILE", "MCPP_BASELINE", "MCPP_ARGS")},
        "MCPP_ACTION_TOKEN": "",
    }
    bash = shutil.which("bash")
    assert bash
    result = subprocess.run(  # noqa: S603
        [bash, "--noprofile", "--norc", "-e", "-o", "pipefail", str(script)],
        env=env,
        check=False,
    )
    assert result.returncode == 0
    assert "exit-code=1" in output.read_text(encoding="utf-8").splitlines()
    args = argv.read_text(encoding="utf-8").splitlines()
    # The action's lock file is used as is, never re-resolved.
    assert args[:6] == ["run", "--quiet", "--frozen", "--no-dev", "--project", str(ROOT)]
    # Targets come last, after `--`, trimmed: a target line can never become an option.
    sep = args.index("--")
    assert args[sep + 1 :] == ["https://mcp.example.com/mcp", "--token-file /etc/passwd", "it's"]
    assert "--token-file" not in args[:sep]


PINNED_ACTION = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def test_third_party_actions_and_images_are_pinned() -> None:
    """Every action is pinned to a commit SHA and every base image to a digest."""
    workflows = [p.relative_to(ROOT).as_posix() for p in (ROOT / ".github/workflows").glob("*.yml")]
    for path in ["action.yml", *workflows]:
        doc = load(path)
        steps: list[dict[str, Any]] = list(doc.get("runs", {}).get("steps", []))
        for job in (doc.get("jobs") or {}).values():
            steps += job.get("steps", [])
        for step in steps:
            uses = step.get("uses")
            if uses and not uses.startswith("./"):
                assert PINNED_ACTION.match(uses), (path, uses)
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    images = re.findall(r"^FROM (\S+)|--from=(\S+:\S+)", dockerfile, re.M)
    refs = [a or b for a, b in images]
    assert refs
    for ref in refs:
        assert re.search(r"@sha256:[0-9a-f]{64}$", ref), ref
